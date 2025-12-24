use std::{
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    task::{Context, Poll},
};

use compact_encoding::CompactEncoding;
use dht_rpc::{
    cenc::generic_hash,
    commit::Commit,
    io::{InResponse, OutRequestBuilder},
    AsyncRpcDht, DhtConfig, IdBytes, Peer, QueryNext, RpcDhtRequestFuture,
};
use futures::{future::join_all, stream::FuturesUnordered, Stream, StreamExt};
use hypercore_protocol::sstream::sm2::Machine;
use tracing::{error, instrument, trace};

use crate::{
    cenc::{
        firewall, NoisePayload, NoisePayloadBuilder, PeerHandshakePayloadBuilder, UdxInfoBuilder,
    },
    commands,
    crypto::PublicKey,
    decode_peer_handshake_response, namespace,
    next_router::{connection::Connection, StreamIdMaker},
    queries::QueryResult,
    request_announce_or_unannounce_value, Error, Keypair, Result, DEFAULT_BOOTSTRAP,
};

pub struct Dht {
    rpc: AsyncRpcDht,
    id_maker: StreamIdMaker,
}

impl Dht {
    pub async fn with_config(mut config: DhtConfig) -> Result<Self> {
        if config.bootstrap_nodes.is_empty() {
            for addr_str in DEFAULT_BOOTSTRAP.iter() {
                if let Some(addr) = addr_str.to_socket_addrs()?.last() {
                    config.bootstrap_nodes.push(addr)
                }
            }
        }

        Ok(Self {
            rpc: AsyncRpcDht::with_config(config).await?,
            id_maker: StreamIdMaker::new(),
        })
    }

    pub async fn boostrap(&self) -> Result<()> {
        self.rpc.bootstrap().await?;
        Ok(())
    }

    pub fn lookup(&self, target: IdBytes, commit: Commit) -> Result<Lookup> {
        let query = self.rpc.query_next(commands::LOOKUP, target, None, commit);
        Ok(Lookup {
            query,
            topic: target,
            collected_responses: Vec::new(),
        })
    }

    pub fn find_peer(&self, pub_key: PublicKey) -> Result<FindPeer> {
        let target = IdBytes(generic_hash(&*pub_key));
        let query = self
            .rpc
            .query_next(commands::FIND_PEER, target, None, Commit::No);
        Ok(FindPeer {
            query,
            topic: target,
            collected_responses: Vec::new(),
        })
    }

    // TODO  return something more useful, maybe indicate if commits failed, etc
    pub async fn announce(
        &self,
        target: IdBytes,
        key_pair: Keypair,
        relay_addresses: Vec<SocketAddr>,
    ) -> Result<()> {
        let query = self
            .rpc
            .query_next(commands::LOOKUP, target, None, Commit::No);
        let pending_commits = Announce {
            rpc: self.rpc.clone(),
            query,
            target,
            key_pair: key_pair.clone(),
            relay_addresses,
        }
        .await?;
        join_all(pending_commits).await;
        Ok(())
    }
    pub fn unannounce(&mut self, target: IdBytes, key_pair: Keypair) -> Unannounce {
        let query = self
            .rpc
            .query_next(commands::LOOKUP, target, None, Commit::No);
        Unannounce {
            rpc: self.rpc.clone(),
            query,
            target,
            key_pair: key_pair.clone(),
            done: false.into(),
            pending_requests: Default::default(),
        }
    }

    pub async fn connect(&self, pub_key: PublicKey) -> Result<Connection> {
        let mut query = self.find_peer(pub_key.clone())?;
        while let Some(resp) = query.next().await {
            let Ok(Some(FindPeerResponse { response, .. })) = resp else {
                continue;
            };
            if let Ok(conn) = self
                .peer_handshake(pub_key.clone(), response.request.to.addr)?
                .await
            {
                return Ok(conn);
            }
        }
        todo!()
    }

    pub fn request(&self, o: OutRequestBuilder) -> RpcDhtRequestFuture {
        self.rpc.request_from_builder(o)
    }

    pub fn peer_handshake(
        &self,
        remote_public_key: PublicKey,
        destination: SocketAddr,
    ) -> Result<PeerHandshake> {
        let SocketAddr::V4(addr) = self.rpc.local_addr()? else {
            todo!()
        };
        let mut hs =
            Machine::new_dht_init(None, &remote_public_key, &crate::namespace::PEER_HANDSHAKE)?;
        let udx_local_id = self.id_maker.new_id();
        let np = NoisePayloadBuilder::default()
            .firewall(firewall::OPEN)
            .addresses4(Some(vec![addr]))
            .udx(Some(
                UdxInfoBuilder::default()
                    .reusable_socket(false)
                    .id(udx_local_id as usize)
                    .build()?,
            ))
            .build()?
            .to_encoded_bytes()?;
        hs.handshake_start(&np)?;
        let noise = hs
            .get_next_sendable_message()?
            .expect("we just set payload above. See `.handshake_start(np)`");
        let peer_handshake_payload = PeerHandshakePayloadBuilder::default()
            .noise(noise)
            .mode(crate::cenc::HandshakeSteps::FromClient)
            .build()?
            .to_encoded_bytes()?;
        let half_stream = self.rpc.socket().create_stream(udx_local_id)?;
        let connection = Connection::new(hs, udx_local_id, half_stream);

        let o = OutRequestBuilder::new(Peer::new(destination), commands::PEER_HANDSHAKE)
            .value(peer_handshake_payload.into())
            .target(generic_hash(&*remote_public_key).into());

        Ok(PeerHandshake {
            request: self.request(o),
            connection,
        })
    }

    pub fn announce_clear(
        &self,
        target: IdBytes,
        key_pair: Keypair,
        relay_addresses: Vec<SocketAddr>,
    ) -> AnnounceClear {
        let query = self
            .rpc
            .query_next(commands::LOOKUP, target, None, Commit::No);
        AnnounceClear {
            rpc: self.rpc.clone(),
            query,
            target,
            key_pair,
            pending_requests: Default::default(),
            relay_addresses,
            query_done: false.into(),
            commits_done: false.into(),
        }
    }
}

#[derive(Debug)]
pub struct PeerHandshake {
    request: RpcDhtRequestFuture,
    connection: Connection,
}

impl Future for PeerHandshake {
    type Output = Result<Connection>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let resp = match Pin::new(&mut self.request).poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(resp)) => resp,
        };

        let phs = decode_peer_handshake_response(&resp)?;
        let hypercore_protocol::sstream::sm2::Event::HandshakePayload(payload) =
            self.connection.receive_next(phs.noise.clone())?
        else {
            todo!()
        };
        let (np, rest) = NoisePayload::decode(&payload)?;
        debug_assert!(rest.is_empty());
        if phs.relayed {
            return Poll::Ready(Err(Error::PeerHandshakeFailed(
                "relay not implemented yet".into(),
            )));
        }

        self.connection.connect(
            resp.request.to.addr,
            np.udx
                .as_ref()
                .expect("TODO response SHOULD have udx_info")
                .id as u32,
            np,
        )?;
        Poll::Ready(Ok(self.connection.clone()))
    }
}

#[derive(Debug)]
pub struct LookupResponse {
    pub response: Arc<InResponse>,
    pub peers: Vec<crate::cenc::Peer>,
}

impl LookupResponse {
    #[instrument(skip_all, err)]
    fn decode_response(response: Arc<InResponse>) -> Result<Option<LookupResponse>> {
        let Some(value) = &response.response.value else {
            return Ok(None);
        };
        let (peers, _rest): (Vec<crate::cenc::Peer>, &[u8]) =
            <Vec<crate::cenc::Peer> as CompactEncoding>::decode(value)?;
        debug_assert!(_rest.is_empty());
        Ok(Some(LookupResponse { response, peers }))
    }
}

#[derive(Debug)]
pub struct Lookup {
    query: QueryNext,
    topic: IdBytes,
    collected_responses: Vec<Arc<InResponse>>,
}

impl Stream for Lookup {
    type Item = Result<Option<LookupResponse>>;

    #[instrument(skip_all)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.query).poll_next(cx).map(|x| {
            x.map(|response| {
                self.collected_responses.push(response.clone());
                LookupResponse::decode_response(response)
            })
        })
    }
}

impl Future for Lookup {
    type Output = Result<QueryResult>;

    #[instrument(skip_all)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut self.query).poll_next(cx) {
                Poll::Ready(Some(response)) => self.collected_responses.push(response),
                Poll::Ready(None) => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.query).poll(cx) {
            Poll::Ready(Ok(query_result)) => Poll::Ready(Ok(QueryResult {
                topic: self.topic,
                responses: std::mem::take(&mut self.collected_responses),
                query_id: query_result.query_id,
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug)]
pub struct FindPeerResponse {
    pub response: Arc<InResponse>,
    pub peer: crate::cenc::Peer,
}

impl FindPeerResponse {
    #[instrument(skip_all, err)]
    fn decode_response(response: Arc<InResponse>) -> Result<Option<FindPeerResponse>> {
        let Some(value) = &response.response.value else {
            return Ok(None);
        };
        let (peer, _rest): (crate::cenc::Peer, &[u8]) =
            <crate::cenc::Peer as CompactEncoding>::decode(value)?;
        debug_assert!(_rest.is_empty());
        Ok(Some(FindPeerResponse { response, peer }))
    }
}

pub struct FindPeer {
    query: QueryNext,
    topic: IdBytes,
    collected_responses: Vec<Arc<InResponse>>,
}

impl Stream for FindPeer {
    type Item = Result<Option<FindPeerResponse>>;

    #[instrument(skip_all)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.query).poll_next(cx).map(|x| {
            x.map(|response| {
                self.collected_responses.push(response.clone());
                FindPeerResponse::decode_response(response)
            })
        })
    }
}

impl Future for FindPeer {
    type Output = Result<QueryResult>;

    #[instrument(skip_all)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut self.query).poll_next(cx) {
                Poll::Ready(Some(response)) => self.collected_responses.push(response),
                Poll::Ready(None) => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.query).poll(cx) {
            Poll::Ready(Ok(query_result)) => Poll::Ready(Ok(QueryResult {
                topic: self.topic,
                responses: std::mem::take(&mut self.collected_responses),
                query_id: query_result.query_id,
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct Announce {
    rpc: AsyncRpcDht,
    query: QueryNext,
    target: IdBytes,
    key_pair: Keypair,
    relay_addresses: Vec<SocketAddr>,
}

impl Future for Announce {
    type Output = Result<Vec<RpcDhtRequestFuture>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.query).poll(cx) {
            Poll::Ready(Ok(query_result)) => {
                let mut requests: Vec<RpcDhtRequestFuture> = vec![];
                for reply in query_result.closest_replies.iter() {
                    let Some(token) = reply.response.token else {
                        todo!("could not get token");
                    };
                    let value = request_announce_or_unannounce_value(
                        &self.key_pair,
                        self.target,
                        &token,
                        reply.request.to.id.expect("request.to.id TODO").into(),
                        &self.relay_addresses,
                        &crate::crypto::namespace::ANNOUNCE,
                    );
                    let from_peer = Peer {
                        id: reply.request.to.id,
                        addr: reply.request.to.addr,
                        referrer: None,
                    };
                    let o = OutRequestBuilder::new(from_peer, crate::commands::ANNOUNCE)
                        .target(self.target)
                        .value(value)
                        .token(token);
                    requests.push(self.rpc.request_from_builder(o));
                }
                Poll::Ready(Ok(requests))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct Unannounce {
    rpc: AsyncRpcDht,
    query: QueryNext,
    target: IdBytes,
    key_pair: Keypair,
    pending_requests: FuturesUnordered<RpcDhtRequestFuture>,
    done: AtomicBool,
}

impl Future for Unannounce {
    type Output = Result<()>;

    // Send a request for each response, push into FuturesUnordered.
    // poll FuturesUnordered for each poll call.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !&self.done.load(Relaxed) {
            match Pin::new(&mut self.query).poll_next(cx) {
                Poll::Ready(Some(resp)) => {
                    let (Some(token), Some(id), commands::LOOKUP) =
                        (&resp.response.token, &resp.valid_peer_id(), resp.cmd())
                    else {
                        todo!("Don't have good stuf!!!!");
                    };
                    let destination = Peer {
                        addr: resp.peer.addr,
                        id: Some(id.0),
                        referrer: None,
                    };
                    let value = request_announce_or_unannounce_value(
                        &self.key_pair,
                        self.target,
                        token,
                        *id,
                        &[],
                        &namespace::UNANNOUNCE,
                    );

                    let o = OutRequestBuilder::new(destination, crate::commands::UNANNOUNCE)
                        .target(self.target)
                        .value(value)
                        .token(*token);
                    let req = self.rpc.request_from_builder(o);
                    trace!(tid = req.tid(), "TX unannounce commit");
                    self.pending_requests.push(req);
                }
                Poll::Ready(None) => {
                    self.done.store(true, Relaxed);
                }
                Poll::Pending => {}
            }
        }
        match Pin::new(&mut self.pending_requests).poll_next(cx) {
            Poll::Ready(Some(Ok(res))) => {
                trace!(tid = res.request.tid, "RX unannounce commit");
                cx.waker().wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => error!(error =? e, "Unannounce commit request error"),
            Poll::Ready(None) => {
                if self.done.load(Relaxed) {
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Pending => {}
        }
        Poll::Pending
    }
}

pub struct AnnounceClear {
    rpc: AsyncRpcDht,
    query: QueryNext,
    target: IdBytes,
    key_pair: Keypair,
    pending_requests: FuturesUnordered<RpcDhtRequestFuture>,
    relay_addresses: Vec<SocketAddr>,
    query_done: AtomicBool,
    commits_done: AtomicBool,
}

impl AnnounceClear {
    fn do_query(&mut self, cx: &mut Context<'_>) -> Option<Poll<Result<()>>> {
        if self.query_done.load(Relaxed) {
            return None;
        }
        match Pin::new(&mut self.query).poll_next(cx) {
            Poll::Ready(Some(resp)) => {
                let (Some(token), Some(id), commands::LOOKUP) =
                    (&resp.response.token, &resp.valid_peer_id(), resp.cmd())
                else {
                    todo!("Don't have good stuf!!!!");
                };
                let destination = Peer {
                    addr: resp.peer.addr,
                    id: Some(id.0),
                    referrer: None,
                };
                let value = request_announce_or_unannounce_value(
                    &self.key_pair,
                    self.target,
                    token,
                    *id,
                    &[],
                    &namespace::UNANNOUNCE,
                );

                let o = OutRequestBuilder::new(destination, crate::commands::UNANNOUNCE)
                    .target(self.target)
                    .value(value)
                    .token(*token);
                let req = self.rpc.request_from_builder(o);
                trace!(tid = req.tid(), "TX unannounce commit");
                self.pending_requests.push(req);
            }
            Poll::Ready(None) => {
                self.query_done.store(true, Relaxed);
            }
            Poll::Pending => {}
        }
        Some(Poll::Pending)
    }
    fn do_commit(&mut self, cx: &mut Context<'_>) -> Option<Poll<Result<()>>> {
        if self.commits_done.load(Relaxed) {
            return None;
        }
        match Pin::new(&mut self.query).poll(cx) {
            Poll::Ready(Ok(query_result)) => {
                for reply in query_result.closest_replies.iter() {
                    let Some(token) = reply.response.token else {
                        todo!("could not get token");
                    };
                    let value = request_announce_or_unannounce_value(
                        &self.key_pair,
                        self.target,
                        &token,
                        reply.request.to.id.expect("request.to.id TODO").into(),
                        &self.relay_addresses,
                        &crate::crypto::namespace::ANNOUNCE,
                    );
                    let from_peer = Peer {
                        id: reply.request.to.id,
                        addr: reply.request.to.addr,
                        referrer: None,
                    };
                    let o = OutRequestBuilder::new(from_peer, crate::commands::ANNOUNCE)
                        .target(self.target)
                        .value(value)
                        .token(token);
                    self.pending_requests.push(self.rpc.request_from_builder(o));
                }
                self.commits_done.store(true, Relaxed);
            }
            Poll::Ready(Err(e)) => return Some(Poll::Ready(Err(e.into()))),
            Poll::Pending => return Some(Poll::Pending),
        }
        None
    }

    fn poll_pending_requests(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match Pin::new(&mut self.pending_requests).poll_next(cx) {
            Poll::Ready(Some(Ok(res))) => {
                trace!(tid = res.request.tid, "RX AnnounceClear commit");
                cx.waker().wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => {
                error!(error =? e, "AnnounceClear commit request error")
            }
            Poll::Ready(None) => {
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => {}
        }
        Poll::Pending
    }
}

impl Future for AnnounceClear {
    type Output = Result<()>;

    // Send a request for each response, push into FuturesUnordered.
    // poll FuturesUnordered for each poll call.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(x) = self.do_query(cx) {
            _ = self.poll_pending_requests(cx);
            return x;
        }
        if let Some(x) = self.do_commit(cx) {
            _ = self.poll_pending_requests(cx);
            return x;
        }
        self.poll_pending_requests(cx)
    }
}
