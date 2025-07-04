use std::{future::Future, mem::take, pin::Pin, sync::Arc, task::Poll};

use crate::{
    commands,
    crypto::{namespace, Keypair},
    request_announce_or_unannounce_value, HyperDhtEvent, Result,
};
use futures::{stream::FuturesUnordered, Stream};

use compact_encoding::CompactEncoding;
use dht_rpc::{
    io::{InResponse, IoHandler},
    query::QueryId,
    IdBytes, Peer, PeerId, RequestFuture, RequestMsgDataInner,
};
use tracing::{error, instrument, trace, warn};

mod announce_clear;
pub use announce_clear::{AnnounceClearResult, AunnounceClearInner};

#[derive(Debug)]
pub struct QueryResult {
    pub topic: IdBytes,
    pub responses: Vec<Arc<InResponse>>,
    pub query_id: QueryId,
}

impl QueryResult {
    fn new(topic: IdBytes, responses: Vec<Arc<InResponse>>, query_id: QueryId) -> Self {
        Self {
            topic,
            responses,
            query_id,
        }
    }
}

#[derive(Debug)]
pub struct LookupInner {
    done: bool,
    pub query_id: QueryId,
    pub topic: IdBytes,
    pub peers: Vec<Arc<InResponse>>,
}

impl LookupInner {
    pub fn new(query_id: QueryId, topic: IdBytes) -> Self {
        Self {
            done: false,
            query_id,
            topic,
            peers: Vec::new(),
        }
    }

    pub fn finalize(&mut self) {
        self.done = true;
    }

    /// Store the decoded peers from the `Response` value
    #[instrument(skip_all)]
    pub fn inject_response(&mut self, resp: Arc<InResponse>) -> Option<HyperDhtEvent> {
        self.peers.push(resp.clone());
        match LookupResponse::from_response(resp) {
            Ok(Some(evt)) => {
                trace!("Decoded valid lookup response");
                Some(HyperDhtEvent::LookupResponse(evt))
            }
            Ok(None) => {
                trace!("Lookup respones missing value field");
                None
            }
            Err(e) => {
                error!(error = display(e), "Error decoding lookup response");
                None
            }
        }
    }
}

#[derive(Debug)]
pub struct LookupResponse {
    pub response: Arc<InResponse>,
    pub peers: Vec<crate::cenc::Peer>,
}

impl LookupResponse {
    /// `Ok(None)` when lookup response is missing value field.
    #[instrument(skip_all, err)]
    pub fn from_response(resp: Arc<InResponse>) -> Result<Option<Self>> {
        let Some(value) = &resp.response.value else {
            return Ok(None);
        };
        let (peers, _rest): (Vec<crate::cenc::Peer>, &[u8]) =
            <Vec<crate::cenc::Peer> as CompactEncoding>::decode(value)?;
        Ok(Some(LookupResponse {
            response: resp,
            peers,
        }))
    }
}

#[derive(Debug)]
pub struct FindPeerResponse {
    pub response: Arc<InResponse>,
    pub peer: crate::cenc::Peer,
}
impl FindPeerResponse {
    /// `Ok(None)` when lookup response is missing value field.
    #[instrument(skip_all, err)]
    pub fn from_response(resp: Arc<InResponse>) -> Result<Option<Self>> {
        let Some(value) = &resp.response.value else {
            return Ok(None);
        };
        let (peer, _rest) = <crate::cenc::Peer as CompactEncoding>::decode(value)?;
        Ok(Some(FindPeerResponse {
            response: resp,
            peer,
        }))
    }
}

#[derive(Debug)]
pub struct AnnounceInner {
    done: bool,
    query_id: QueryId,
    pub topic: IdBytes,
    pub responses: Vec<Arc<InResponse>>,
    pub keypair: Keypair,
}

impl AnnounceInner {
    pub fn new(query_id: QueryId, topic: IdBytes, keypair: Keypair) -> Self {
        Self {
            done: false,
            query_id,
            topic,
            keypair,
            responses: Default::default(),
        }
    }
    pub fn finalize(&mut self) {
        self.done = true;
    }

    /// Store the decoded peers from the `Response` value
    #[instrument(skip_all)]
    pub fn inject_response(&mut self, resp: Arc<InResponse>) {
        self.responses.push(resp);
    }
}

#[derive(Debug)]
pub struct UnannounceInner {
    /// switched on when query is completed
    done: bool,
    pub topic: IdBytes,
    pub inflight_unannounces: FuturesUnordered<RequestFuture<Arc<InResponse>>>,
    pub keypair: Keypair,
    pub results: Vec<Result<Arc<InResponse>>>,
}

impl UnannounceInner {
    pub fn new(topic: IdBytes, keypair: Keypair) -> Self {
        Self {
            done: false,
            topic,
            keypair,
            inflight_unannounces: Default::default(),
            results: Default::default(),
        }
    }

    /// Store the decoded peers from the `Response` value
    #[instrument(skip_all)]
    pub fn inject_response(
        &mut self,
        io: &mut IoHandler,
        resp: Arc<InResponse>,
        query_id: QueryId,
    ) {
        if let (Some(token), Some(id), commands::LOOKUP) =
            (&resp.response.token, &resp.valid_peer_id(), resp.cmd())
        {
            let destination = PeerId {
                addr: resp.peer.addr,
                id: *id,
            };

            let req = UnannounceRequest {
                keypair: self.keypair.clone(),
                topic: self.topic,
                token: *token,
                destination,
            };
            match io.start_send_next_fut_no_id(Some(query_id), req.into()) {
                Ok(fut) => self.inflight_unannounces.push(fut),
                Err(e) => error!("Erorr sending unannonuce: {e:?}"),
            }
        } else {
            warn!(
                resp.tid = resp.response.tid,
                resp.query_id = display(query_id),
                resp.token = debug(resp.response.token),
                resp.peer_id = debug(resp.valid_peer_id()),
                resp.cmd = display(resp.cmd()),
                "Other kind of response to lookup query"
            );
        };
    }

    pub fn finalize(&mut self) {
        self.done = true;
    }
}

impl Future for UnannounceInner {
    type Output = Result<UnannounceResult>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        while let Poll::Ready(Some(result)) = Pin::new(&mut self.inflight_unannounces).poll_next(cx)
        {
            self.results.push(result.map_err(|e| e.into()))
        }

        // NB we check results not empty to prevent resolving before an unannounces are sent
        if self.inflight_unannounces.is_empty() && self.done {
            Poll::Ready(Ok(UnannounceResult::new(take(&mut self.results))))
        } else {
            Poll::Pending
        }
    }
}

impl Future for AnnounceInner {
    type Output = Result<QueryResult>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Ok(QueryResult::new(
                self.topic,
                take(&mut self.responses),
                self.query_id,
            )));
        }
        Poll::Pending
    }
}
impl Future for LookupInner {
    type Output = Result<QueryResult>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Ok(QueryResult {
                topic: self.topic,
                responses: take(&mut self.peers),
                query_id: self.query_id,
            }));
        }
        Poll::Pending
    }
}

impl Future for FindPeerInner {
    type Output = Result<QueryResult>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Ok(QueryResult {
                topic: self.topic,
                responses: take(&mut self.peers),
                query_id: self.query_id,
            }));
        }
        Poll::Pending
    }
}

#[derive(Debug)]
pub struct UnannounceResult {
    pub responses: Vec<Result<Arc<InResponse>>>,
}
impl UnannounceResult {
    fn new(responses: Vec<Result<Arc<InResponse>>>) -> Self {
        Self { responses }
    }
}

#[derive(Debug)]
pub struct UnannounceRequest {
    pub keypair: Keypair,
    pub topic: IdBytes,
    pub token: [u8; 32],
    pub destination: PeerId,
}

impl From<UnannounceRequest> for RequestMsgDataInner {
    fn from(
        UnannounceRequest {
            keypair,
            topic,
            token,
            destination,
        }: UnannounceRequest,
    ) -> Self {
        let value = request_announce_or_unannounce_value(
            &keypair,
            topic,
            &token,
            destination.id,
            &[],
            &namespace::UNANNOUNCE,
        );

        let destination = Peer {
            id: Some(destination.id.0),
            addr: destination.addr,
            referrer: None,
        };

        RequestMsgDataInner {
            to: destination,
            token: Some(token),
            command: commands::UNANNOUNCE,
            target: Some(topic.0),
            value: Some(value),
        }
    }
}

#[derive(Debug)]
pub struct FindPeerInner {
    done: bool,
    pub query_id: QueryId,
    pub topic: IdBytes,
    pub peers: Vec<Arc<InResponse>>,
}
impl FindPeerInner {
    pub fn new(query_id: QueryId, topic: IdBytes) -> Self {
        Self {
            done: false,
            query_id,
            topic,
            peers: Vec::new(),
        }
    }
    pub fn finalize(&mut self) {
        self.done = true;
    }

    #[instrument(skip_all)]
    pub fn inject_response(&mut self, resp: Arc<InResponse>) -> Option<HyperDhtEvent> {
        self.peers.push(resp.clone());
        match FindPeerResponse::from_response(resp) {
            Ok(Some(evt)) => {
                trace!("Decoded valid lookup response");
                Some(HyperDhtEvent::FindPeerResponse(evt))
            }
            Ok(None) => {
                trace!("Lookup respones missing value field");
                None
            }
            Err(e) => {
                error!(error = display(e), "Error decoding lookup response");
                None
            }
        }
    }
}
