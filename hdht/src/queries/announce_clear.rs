use std::{future::Future, mem::take, pin::Pin, sync::Arc, task::Poll};

use dht_rpc::{
    io::{InResponse, IoHandler, MessageSender},
    query::{QueryId, QueryResult},
    Command, ExternalCommand, IdBytes, PeerId, RequestFuture, RequestMsgDataInner,
};
use futures::{stream::FuturesUnordered, Stream};
use tracing::{error, warn};

use crate::{
    commands::{ANNOUNCE, LOOKUP},
    crypto::Keypair2,
    request_announce_or_unannounce_value, Result,
};

use super::UnannounceRequest;

#[derive(Debug)]
pub struct AunnounceClearInner {
    /// switched on when query is completed
    done: bool,
    pub topic: IdBytes,
    pub keypair: Keypair2,
    pub responses: Vec<Result<Arc<InResponse>>>,
    pub inflight_unannounces: FuturesUnordered<RequestFuture<Arc<InResponse>>>,
    pub inflight_announces: FuturesUnordered<RequestFuture<Arc<InResponse>>>,
    pub search_complete: Option<(MessageSender, QueryResult)>,
}

impl AunnounceClearInner {
    pub fn new(topic: IdBytes, keypair: Keypair2) -> Self {
        Self {
            done: false,
            topic,
            keypair,
            responses: Default::default(),
            inflight_unannounces: Default::default(),
            inflight_announces: Default::default(),
            search_complete: None,
        }
    }
    /// For each response send an unannounce
    pub fn inject_response(
        &mut self,
        io: &mut IoHandler,
        resp: Arc<InResponse>,
        query_id: QueryId,
    ) {
        if let (Some(token), Some(id), Command::External(ExternalCommand(LOOKUP))) =
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
    pub fn finalize(&mut self, sender: MessageSender, query_result: QueryResult) {
        self.search_complete = Some((sender, query_result));
    }
}

#[derive(Debug)]
pub struct AnnounceClearResult {
    #[allow(unused)]
    pub responses: Vec<Result<Arc<InResponse>>>,
}

impl AnnounceClearResult {
    fn new(responses: Vec<Result<Arc<InResponse>>>) -> Self {
        Self { responses }
    }
}

impl Future for AunnounceClearInner {
    type Output = Result<AnnounceClearResult>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(Some(result)) = Pin::new(&mut self.inflight_unannounces).poll_next(cx)
        {
            self.responses.push(result.map_err(|e| e.into()))
        }

        while let Poll::Ready(Some(result)) = Pin::new(&mut self.inflight_announces).poll_next(cx) {
            self.responses.push(result.map_err(|e| e.into()))
        }

        // When we have search_complete, take it, and make the commits
        if let Some((mut tx, query_result)) = std::mem::take(&mut self.search_complete) {
            for cr in query_result.closest_replies.iter() {
                let value = Some(request_announce_or_unannounce_value(
                    &self.keypair,
                    self.topic,
                    &cr.response.token.expect("TODO"),
                    cr.request.to.id.expect("TODO").into(),
                    &[],
                    &crate::crypto::namespace::ANNOUNCE,
                ));
                let msg = RequestMsgDataInner {
                    to: cr.peer.clone(),
                    // TODO we should have token here. assert?
                    token: cr.response.token,
                    command: Command::External(ExternalCommand(ANNOUNCE)),
                    target: Some(self.topic.0),
                    value,
                };
                let req_fut = tx.send((Some(query_result.query_id), msg)).expect("TODO");
                self.inflight_announces.push(req_fut);
            }
            // No more work to do, we just wait for all requests to finish.
            self.done = true;
        }

        // NB we check results not empty to prevent resolving before an unannounces are sent
        if self.inflight_unannounces.is_empty() && self.inflight_announces.is_empty() && self.done {
            Poll::Ready(Ok(AnnounceClearResult::new(take(&mut self.responses))))
        } else {
            Poll::Pending
        }
    }
}
