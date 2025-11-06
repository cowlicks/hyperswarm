//! Rust Implementation of the hyperswarm DHT
#![warn(rust_2018_idioms)]
#![deny(clippy::enum_glob_use)]

use std::{
    array::TryFromSliceError,
    cmp,
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    fmt,
    future::Future,
    net::{AddrParseError, IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use cenc::{
    NoisePayloadBuilderError, PeerHandshakePayload, PeerHandshakePayloadBuilderError,
    RelayThroughInfoBuilderError, UdxInfoBuilderError,
};
use compact_encoding::{CompactEncoding, EncodingError};
use crypto::PublicKey;
use dht_rpc::{
    commit::{CommitMessage, CommitRequestParams, Progress},
    io::{InResponse, MessageSender, OutRequestBuilder},
    query::{Query, QueryResult as RpcQueryResult},
    RequestFutureError, Tid,
};
use futures::{
    channel::mpsc::{self},
    task::{Context, Poll},
    Stream, StreamExt,
};
use futuresmap::FuturesMap;
use prost::Message as ProstMessage;
use queries::{
    AnnounceClearResult, AnnounceInner, AunnounceClearInner, FindPeerInner, FindPeerResponse,
    LookupInner, LookupResponse, QueryResult, UnannounceInner, UnannounceResult,
};
use smallvec::alloc::collections::VecDeque;
use tokio::sync::oneshot::{self, error::RecvError};
use tracing::{debug, error, instrument, trace, warn};

use crate::{
    dht_proto::{PeersInput, PeersOutput},
    lru::{CacheKey, PeerCache},
    next_router::connection::Connection,
    store::Store,
};
pub use ::dht_rpc::{
    cenc::generic_hash,
    commit::Commit,
    peers::{decode_local_peers, decode_peers, PeersEncoding},
    query::{CommandQuery, QueryId, QueryStats},
    Command, DhtConfig, ExternalCommand, IdBytes, Peer, PeerId, RequestMsgData, RequestOk,
    ResponseOk, RpcDht, RpcDhtBuilderError, RpcDhtEvent,
};

mod dht_proto {
    include!(concat!(env!("OUT_DIR"), "/dht_pb.rs"));
}
pub mod cenc;
mod crypto;
mod futuresmap;
pub mod lru;
mod next_router;
mod queries;
mod store;

pub use crypto::{
    make_signable_announce_or_unannounce, namespace, sign_announce_or_unannounce, Keypair,
};

/// The publicly available hyperswarm DHT addresses
pub const DEFAULT_BOOTSTRAP: [&str; 3] = [
    "node1.hyperdht.org:49737",
    "node2.hyperdht.org:49737",
    "node3.hyperdht.org:49737",
];

pub(crate) const ERR_INVALID_INPUT: usize = 7;
pub(crate) const ERR_INVALID_SEQ: usize = 11;
pub(crate) const ERR_SEQ_MUST_EXCEED_CURRENT: usize = 13;

pub mod commands {
    use dht_rpc::{Command, ExternalCommand};

    pub const PEER_HANDSHAKE: Command = Command::External(ExternalCommand(values::PEER_HANDSHAKE));
    pub const PEER_HOLEPUNCH: Command = Command::External(ExternalCommand(values::PEER_HOLEPUNCH));
    pub const FIND_PEER: Command = Command::External(ExternalCommand(values::FIND_PEER));
    pub const LOOKUP: Command = Command::External(ExternalCommand(values::LOOKUP));
    pub const ANNOUNCE: Command = Command::External(ExternalCommand(values::ANNOUNCE));
    pub const UNANNOUNCE: Command = Command::External(ExternalCommand(values::UNANNOUNCE));
    pub mod values {
        pub const PEER_HANDSHAKE: usize = 0;
        pub const PEER_HOLEPUNCH: usize = 1;
        pub const FIND_PEER: usize = 2;
        pub const LOOKUP: usize = 3;
        pub const ANNOUNCE: usize = 4;
        pub const UNANNOUNCE: usize = 5;
    }
}
/// The command identifier for `Mutable` storage
pub const MUTABLE_STORE_CMD: usize = 1;
/// The command identifier for immutable storage
pub const IMMUTABLE_STORE_CMD: usize = 2;
/// The command identifier to (un)announce/lookup peers
pub const PEERS_CMD: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error from dht_rpc: {0}")]
    RpcError(#[from] ::dht_rpc::Error),
    #[error("Error from compact_encoding: {0}")]
    CompactEncodingError(EncodingError),
    #[error("IO Eror")]
    IoError(#[from] std::io::Error),
    #[error("Invalid RPC command in message: {0}")]
    InvalidRpcCommand(u8),
    #[error("Incorrect message ID size. Expected 32. Error: {0}")]
    IncorrectMessageIdSize(TryFromSliceError),
    #[error("Error in libsodium's genric_hash function. Return value: {0}")]
    LibSodiumGenericHashError(i32),
    #[error("RpcDhtBuilderError: {0}")]
    RpcDhtBuilderError(#[from] RpcDhtBuilderError),
    #[error("RecvError: {0}")]
    RecvError(#[from] RecvError),
    #[error("AddrParseError: {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("Requests must have a 'to' field")]
    RequestRequiresToField,
    #[error("Ipv6 not supported")]
    Ipv6NotSupported,
    #[error("Invalid Signature")]
    InvalidSignature(i32),
    #[error("Future Request error")]
    FutureRequestFailed(#[from] RequestFutureError),
    #[error("Error building PeerHandshakePayload: {0}")]
    PeerHandshakePayloadBuilder(#[from] PeerHandshakePayloadBuilderError),
    #[error("Error building UdxInfo: {0}")]
    UdxInfoBuilder(#[from] UdxInfoBuilderError),
    #[error("Error building NoisePaylod: {0}")]
    NoisePayloadBuilder(#[from] NoisePayloadBuilderError),
    #[error("Error building RelayThroughInfo: {0}")]
    RelayThroughInfoBuilder(#[from] RelayThroughInfoBuilderError),
    #[error("Hypercore Protocol Error: {0}")]
    HypercoreProtocolError(#[from] hypercore_protocol::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// TODO make EncodingError impl Error trait
impl From<EncodingError> for Error {
    fn from(value: EncodingError) -> Self {
        Error::CompactEncodingError(value)
    }
}

/// The implementation of the hyperswarm DHT
#[derive(Debug)]
pub struct HyperDhtInner {
    /// The underlying Rpc DHT including IO
    rpc: RpcDht,
    /// Map to track the queries currently in progress
    queries: FuturesMap<QueryId, QueryStreamType>,
    /// If `true`, the node will become non-ephemeral after the node has shown, to be long-lived
    #[expect(unused)] // FIXME why aint this used
    adaptive: bool,
    /// Cache for known peers
    peers: PeerCache,
    /// Storage for the mutable/immutable values
    store: Store,
    /// Queued events to return when being polled.
    queued_events: VecDeque<HyperDhtEvent>,
    /// Default keypair
    #[expect(unused)] // TODO
    default_keypair: Keypair,
    /// Router for peer connections
    router: next_router::Router,
    /// Channels to send FindPeerResponse through for pending find_peer queries
    pending_find_peers: BTreeMap<QueryId, oneshot::Sender<FindPeerResponse>>,
}

impl HyperDhtInner {
    /// Create a new DHT based on the configuration
    pub async fn with_config(mut config: DhtConfig) -> Result<Self> {
        if config.bootstrap_nodes.is_empty() {
            for addr_str in DEFAULT_BOOTSTRAP.iter() {
                if let Some(addr) = addr_str.to_socket_addrs()?.last() {
                    config.bootstrap_nodes.push(addr)
                }
            }
        }

        Ok(Self {
            adaptive: config.adaptive,
            queries: Default::default(),
            rpc: RpcDht::with_config(config).await?,
            // peer cache with 25 min timeout
            peers: PeerCache::new(65536, Duration::from_secs(60 * 25)),
            store: Store::new(5000),
            queued_events: Default::default(),
            default_keypair: Default::default(),
            router: Default::default(),
            pending_find_peers: BTreeMap::new(),
        })
    }

    /// The local address of the underlying `UdpSocket`
    #[inline]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.rpc.local_addr()?)
    }

    /// Handle an incoming requests for the registered commands and reply.
    fn on_command(&mut self, q: CommandQuery, request: RequestMsgData, peer: Peer) {
        match q.command {
            MUTABLE_STORE_CMD => {
                let resp = self.store.on_command_mut(q);
                self.rpc.reply_command(resp)
            }
            IMMUTABLE_STORE_CMD => {
                let resp = self.store.on_command(q);
                self.rpc.reply_command(resp)
            }
            PEERS_CMD => self.on_peers(q),
            command => self
                .queued_events
                .push_back(HyperDhtEvent::CustomCommandQuery {
                    command,
                    msg: Box::new(request),
                    peer,
                }),
        }
    }
    /// Callback for an incoming `peers` command query
    fn on_peers(&mut self, mut query: CommandQuery) {
        // decode the received value
        if let Some(ref val) = query.value {
            if let Ok(peer) = PeersInput::decode(&**val) {
                // callback
                let port = peer
                    .port
                    .and_then(|port| u16::try_from(port).ok())
                    .unwrap_or_else(|| query.peer.addr.port());

                if let IpAddr::V4(host) = query.peer.addr.ip() {
                    let from = SocketAddr::V4(SocketAddrV4::new(host, port));

                    let remote_cache = CacheKey::Remote(query.target);

                    let local_cache = peer.local_address.as_ref().and_then(|l| {
                        if l.len() == 6 {
                            let prefix: [u8; 2] = l[0..2].try_into().unwrap();
                            let suffix: [u8; 4] = l[2..].try_into().unwrap();
                            Some((
                                CacheKey::Local {
                                    id: query.target,
                                    prefix,
                                },
                                suffix,
                            ))
                        } else {
                            None
                        }
                    });

                    let local_peers = if let Some((local_cache, suffix)) = local_cache {
                        self.peers.get(&local_cache).and_then(|addrs| {
                            addrs.iter_locals().map(|locals| {
                                locals
                                    .filter(|s| **s != suffix)
                                    .flat_map(|s| s.iter())
                                    .cloned()
                                    .take(32)
                                    .collect::<Vec<_>>()
                            })
                        })
                    } else {
                        None
                    };

                    let peers = if let Some(remotes) = self
                        .peers
                        .get(&remote_cache)
                        .and_then(|addrs| addrs.remotes())
                    {
                        let num = cmp::min(
                            remotes.len(),
                            128 - local_peers.as_ref().map(|l| l.len()).unwrap_or_default(),
                        );
                        let mut buf = Vec::with_capacity(num * 6);

                        for addr in remotes.iter().filter(|addr| **addr != from).take(num) {
                            if let IpAddr::V4(ip) = addr.ip() {
                                buf.extend_from_slice(&ip.octets()[..]);
                                buf.extend_from_slice(&addr.port().to_be_bytes()[..]);
                            }
                        }
                        Some(buf)
                    } else {
                        None
                    };

                    let output = PeersOutput { peers, local_peers };
                    let mut buf = Vec::with_capacity(output.encoded_len());

                    // fits safe in vec
                    output.encode(&mut buf).unwrap();
                    query.value = Some(buf);
                    self.rpc.reply_command(query.into());
                    return;
                }
                let _ = query.value.take();
                self.rpc.reply_command(query.into());
            }
        }
    }

    pub fn find_peer(&mut self, pub_key: PublicKey) -> QueryId {
        let target = IdBytes(generic_hash(&*pub_key));

        let query_id = self
            .rpc
            .query(commands::FIND_PEER, target, None, Commit::No);
        self.queries.insert(
            query_id,
            QueryStreamType::FindPeer(FindPeerInner::new(query_id, target)),
        );
        query_id
    }

    /// Store a channel sender for a find_peer query result
    fn store_find_peer_sender(&mut self, query_id: QueryId, tx: oneshot::Sender<FindPeerResponse>) {
        self.pending_find_peers.insert(query_id, tx);
    }

    /// Initiates an iterative query to the closest peers to lookup the topic.
    ///
    /// The result of the query is delivered in a
    /// [`HyperDhtEvent::LookupResult`].
    pub fn lookup(&mut self, target: IdBytes, commit: Commit) -> QueryId {
        let query_id = self.rpc.query(commands::LOOKUP, target, None, commit);
        self.queries.insert(
            query_id,
            QueryStreamType::Lookup(LookupInner::new(query_id, target)),
        );
        query_id
    }

    /// Announce the topic to the closest peers
    ///
    /// Query result is a [`HyperDhtEvent::AnnounceResult`].
    pub fn announce(
        &mut self,
        target: IdBytes,
        key_pair: &Keypair,
        _relay_addresses: &[SocketAddr],
    ) -> QueryId {
        let qid = self.rpc.query(
            commands::LOOKUP,
            target,
            None,
            Commit::Custom(Progress::default()),
        );
        self.queries.insert(
            qid,
            QueryStreamType::Announce(AnnounceInner::new(qid, target, key_pair.clone())),
        );
        qid
    }

    /// Announce the topic to the closest peers, send unnanounce while doing so
    ///
    /// Query result is a [`HyperDhtEvent::AnnounceResult`].
    pub fn announce_clear(
        &mut self,
        target: IdBytes,
        key_pair: &Keypair,
        _relay_addresses: &[SocketAddr],
    ) -> QueryId {
        let qid = self.rpc.query(
            commands::LOOKUP,
            target,
            None,
            Commit::Custom(Progress::default()),
        );
        self.queries.insert(
            qid,
            QueryStreamType::AnnounceClear(AunnounceClearInner::new(target, key_pair.clone())),
        );
        qid
    }

    /// Initiates an iterative query to unannounce the topic to the closest
    /// peers.
    ///
    /// The result of the query is delivered in a
    /// [`HyperDhtEvent::UnAnnounceResult`].
    pub fn unannounce(&mut self, target: IdBytes, key_pair: &Keypair) -> QueryId {
        let qid = self.rpc.query(commands::LOOKUP, target, None, Commit::No);
        self.queries.insert(
            qid,
            QueryStreamType::UnAnnounce(UnannounceInner::new(target, key_pair.clone())),
        );
        qid
    }

    #[instrument(skip_all)]
    fn inject_response(&mut self, resp: Arc<InResponse>, _cx: &mut Context<'_>) {
        trace!(
            cmd = display(resp.cmd()),
            "Handle Response for custom command"
        );
        // Holding `&mut query` here prevents us from calling self.request_unannounce
        // maybe instead we return something from the block to do the msg that we want?
        // however I want to pass in an id from the request.
        // I really just want a mut ref to the query, but
        //
        // Handle responses to queries
        if let Some((query, qid)) = resp
            .query_id
            .and_then(|qid| self.queries.get_mut(&qid).map(|q| (q, qid)))
        {
            let event = {
                match query.deref_mut() {
                    QueryStreamType::Announce(inner) => {
                        inner.inject_response(resp);
                        None
                    }
                    QueryStreamType::UnAnnounce(inner) => {
                        inner.inject_response(&mut self.rpc.io, resp, qid);
                        None
                    }
                    QueryStreamType::Lookup(inner) => inner.inject_response(resp.clone()),
                    QueryStreamType::AnnounceClear(inner) => {
                        inner.inject_response(&mut self.rpc.io, resp, qid);
                        None
                    }
                    QueryStreamType::FindPeer(inner) => {
                        if let Some(fp_resp) = inner.inject_response(resp.clone()) {
                            // Send the response through the channel if one is waiting
                            if let Some(tx) = self.pending_find_peers.remove(&qid) {
                                let response_to_send = FindPeerResponse {
                                    response: fp_resp.response.clone(),
                                    peer: fp_resp.peer.clone(),
                                };
                                let _ = tx.send(response_to_send);
                            }
                            Some(HyperDhtEvent::FindPeerResponse(fp_resp))
                        } else {
                            None
                        }
                    }
                }
            };
            if let Some(e) = event {
                self.queued_events.push_back(e);
            }
        } else {
            // handle respones to non-queries
            match resp.request.command {
                Command::Internal(_) => {
                    // TODO
                }
                commands::PEER_HANDSHAKE => {
                    match PeerHandshakePayload::decode(
                        &resp.response.value.clone().expect("with value"),
                    ) {
                        Ok((hs, rest)) => {
                            let _ = self.router.inject_response(
                                &resp,
                                hs,
                                &mut |e| self.queued_events.push_back(e),
                                self.rpc.socket(),
                            );
                            debug_assert!(rest.is_empty(), "respones completely used")
                        }
                        Err(e) => todo!("{e:?}"),
                    }
                }
                Command::External(_) => {
                    // TODO
                }
            }
        }
    }

    // A query was completed
    fn query_target_search_done(&mut self, query_result: RpcQueryResult) {
        if let Some(query) = self.queries.get_mut(&query_result.query_id) {
            query.target_search_done(self.rpc.io.create_sender(), query_result);
        } else {
            warn!(
                id = ?query_result.query_id,
                "Query with unknown id finished"
            );
        }
    }

    fn commit(&mut self, query: Arc<RwLock<Query>>, channel: mpsc::Sender<CommitMessage>) {
        let id = query.read().unwrap().id();
        let Some(qst) = self.queries.get_mut(&id) else {
            error!("Tried to commit with an unknown query id: [{id:?}]");
            panic!("Tried to commit with an unknown query id: [{id:?}]");
        };
        qst.commit(query, channel);
    }

    pub fn request_peer_handshake(
        &mut self,
        remote_public_key: PublicKey,
        destination: SocketAddrV4,
    ) -> Result<Tid> {
        let tid = self.rpc.new_tid();

        let SocketAddr::V4(addr) = self.local_addr()? else {
            todo!()
        };

        let value = self
            .router
            .first_step(tid, *remote_public_key, Some(vec![addr]), self.rpc.socket())
            .unwrap();
        let req = OutRequestBuilder::default()
            .destination(destination)
            .value(value)
            .target(generic_hash(&*remote_public_key))
            .command(commands::PEER_HANDSHAKE)
            .tid(tid);
        self.rpc.request_from_builder(req)?;
        Ok(tid)
    }

    #[expect(clippy::too_many_arguments)]
    fn request_announce_or_unannounce(
        &mut self,
        keypair: &Keypair,
        target: IdBytes,
        token: &[u8; 32],
        destination: PeerId,
        relay_addresses: &[SocketAddr],
        namespace: &[u8; 32],
        cmd: ExternalCommand,
    ) -> Tid {
        let value = request_announce_or_unannounce_value(
            keypair,
            target,
            token,
            destination.id,
            relay_addresses,
            namespace,
        );

        let from_peer = Peer {
            id: Some(destination.id.0),
            addr: destination.addr,
            referrer: None,
        };

        self.rpc.request(
            Command::External(cmd),
            Some(target),
            Some(value),
            from_peer,
            Some(*token),
        )
    }

    #[expect(unused)] // TODO FIXME
    fn request_announce(
        &mut self,
        keypair: &Keypair,
        target: IdBytes,
        token: &[u8; 32],
        destination: PeerId,
        relay_addresses: &[SocketAddr],
    ) -> Tid {
        // TODO rm result
        self.request_announce_or_unannounce(
            keypair,
            target,
            token,
            destination,
            relay_addresses,
            &crate::crypto::namespace::ANNOUNCE,
            ExternalCommand(commands::values::ANNOUNCE),
        )
    }

    #[expect(unused)] // TODO FIXME
    fn request_unannounce(
        &mut self,
        keypair: &Keypair,
        target: IdBytes,
        token: &[u8; 32],
        destination: PeerId,
    ) -> Tid {
        self.request_announce_or_unannounce(
            keypair,
            target,
            token,
            destination,
            &[],
            &crate::crypto::namespace::UNANNOUNCE,
            ExternalCommand(commands::values::UNANNOUNCE),
        )
    }
}

impl Stream for HyperDhtInner {
    type Item = HyperDhtEvent;

    #[instrument(skip_all)]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        loop {
            // Drain queued events first.
            if let Some(event) = pin.queued_events.pop_front() {
                return Poll::Ready(Some(event));
            }

            // Drain rpc events
            while let Poll::Ready(Some(ev)) = Stream::poll_next(Pin::new(&mut pin.rpc), cx) {
                match ev {
                    RpcDhtEvent::RequestResult(Ok(RequestOk::CustomCommandRequest {
                        query,
                        request,
                        peer,
                    })) => pin.on_command(query, *request, peer),
                    RpcDhtEvent::ResponseResult(Ok(ResponseOk::Response(resp))) => {
                        pin.inject_response(resp, cx)
                    }
                    RpcDhtEvent::Bootstrapped { stats } => {
                        return Poll::Ready(Some(HyperDhtEvent::Bootstrapped { stats }))
                    }
                    RpcDhtEvent::ReadyToCommit {
                        query,
                        tx_commit_messages,
                    } => {
                        pin.commit(query, tx_commit_messages);
                    }
                    RpcDhtEvent::QueryResult(qr) => {
                        pin.query_target_search_done(qr);
                    }
                    _other => warn!("unhandled rpc event"),
                }
            }

            // Poll ongoing queries
            while let Poll::Ready(Some(query_result)) = pin.queries.poll_next_unpin(cx) {
                use HyperDhtEvent as hde;
                use QueryStreamResult as qsr;
                pin.queued_events.push_back(match query_result {
                    Err(_) => todo!("we should just emit this as an error"),
                    Ok(res) => match res {
                        qsr::Lookup(r) => hde::LookupResult(r),
                        qsr::Announce(r) => hde::AnnounceResult(r),
                        qsr::UnAnnounce(r) => hde::UnAnnounceResult(Ok(r)),
                        qsr::AnnounceClear(r) => hde::AnnouncClearResult(Ok(r)),
                        qsr::FindPeer(r) => hde::FindPeerResult(Ok(r)),
                    },
                })
            }

            // No immediate event was produced as a result of the DHT.
            // If no new events have been queued either, signal `Pending` to
            // be polled again later.
            if pin.queued_events.is_empty() {
                return Poll::Pending;
            }
        }
    }
}

pub struct HyperDht {
    inner: Arc<Mutex<HyperDhtInner>>,
}

/// Future that resolves when a FindPeerResponse is received for the find_peer query
pub struct FindPeerFuture {
    inner: Arc<Mutex<HyperDhtInner>>,
    rx: oneshot::Receiver<FindPeerResponse>,
}

impl Future for FindPeerFuture {
    type Output = Result<FindPeerResponse>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Poll the inner to drive the find_peer query forward
        {
            let mut inner = self.inner.lock().unwrap();
            let _ = Stream::poll_next(Pin::new(&mut *inner), cx);
        }

        // Poll the receiver for the response
        Pin::new(&mut self.rx).poll(cx).map_err(Error::RecvError)
    }
}

impl HyperDht {
    pub async fn with_config(config: DhtConfig) -> Result<Self> {
        let inner = HyperDhtInner::with_config(config).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }
    /// Initiate a find_peer query for the given public key.
    ///
    /// Returns a future that resolves with the first FindPeerResponse received,
    /// or an error if the query fails.
    pub fn find_peer(&mut self, pub_key: PublicKey) -> FindPeerFuture {
        let (tx, rx) = oneshot::channel();

        {
            let mut inner = self.inner.lock().unwrap();
            let query_id = inner.find_peer(pub_key);
            inner.store_find_peer_sender(query_id, tx);
        }

        FindPeerFuture {
            inner: self.inner.clone(),
            rx,
        }
    }
}

/// Events
///
/// The events produced by the `HyperDht` behaviour.
///
/// See [`HyperDht::poll`].
// TODO should this be refactored into...
// - enum {
//   Response(ResponseKind) / Ann, Look, etc
//   Result(ResultKind) / Ann, Look, etc
//   ...
// }
// - enum {
//   Announce(Ann/Result/Resp)
//   Lookup(Ann/Result/Resp)
// }
// ... maybe for now just make it flat
#[derive(Debug)]
pub enum HyperDhtEvent {
    /// The dht is now bootstrapped
    Bootstrapped {
        /// Execution statistics from the bootstrap query.
        stats: QueryStats,
    },
    /// The result of [`HyperDht::announce`].
    AnnounceResult(QueryResult),
    /// A response to part of a lookup query
    LookupResponse(LookupResponse),
    /// The result of [`HyperDht::lookup`].
    LookupResult(QueryResult),
    /// The result of [`HyperDht::unannounce`].
    UnAnnounceResult(Result<UnannounceResult>),
    /// The result of [`HyperDht::announce_clear`]
    AnnouncClearResult(Result<AnnounceClearResult>),
    /// A response to part of a find_peer query
    FindPeerResponse(FindPeerResponse),
    /// The result of [`HyperDht::find_peer`].
    FindPeerResult(Result<QueryResult>),
    /// Received a query with a custom command that is not automatically handled
    /// by the DHT
    CustomCommandQuery {
        /// The unknown command
        command: usize,
        /// The message we received from the peer.
        msg: Box<RequestMsgData>,
        /// The peer the message originated from.
        peer: Peer,
    },
    Connected((Tid, Connection)),
}

impl HyperDhtEvent {
    pub fn kind(&self) -> &'static str {
        match &self {
            HyperDhtEvent::Bootstrapped { .. } => "Bootstrapped",
            HyperDhtEvent::AnnounceResult(_) => "AnnounceResult",
            HyperDhtEvent::LookupResponse(_) => "LookupResponse",
            HyperDhtEvent::LookupResult(_) => "LookupResult",
            HyperDhtEvent::UnAnnounceResult(_) => "UnAnnounceResult",
            HyperDhtEvent::AnnouncClearResult(_) => "AnnouncClearResult",
            HyperDhtEvent::FindPeerResponse(_) => "FindPeerResponse",
            HyperDhtEvent::FindPeerResult(_) => "FindPeerResult",
            HyperDhtEvent::CustomCommandQuery { .. } => "CustomCommandQuery",
            HyperDhtEvent::Connected { .. } => "Connected",
        }
    }
}

/// Represents the response received from a peer
#[derive(Debug)]
pub struct PeerResponseItem<T: fmt::Debug> {
    /// Address of the peer this response came from
    pub peer: SocketAddr,
    /// The identifier of the `peer` if included in the response
    pub peer_id: Option<IdBytes>,
    /// The value the `peer` provided
    pub value: T,
}

/// Result of a [`HyperDht::lookup`] query.
#[derive(Debug, Clone)]
pub struct Lookup {
    /// The hash to lookup
    pub topic: IdBytes,
    /// The gathered responses
    pub peers: Vec<Peers>,
}

/// A Response to a query request from a peer
#[derive(Debug, Clone)]
pub struct Peers {
    /// The DHT node that is returning this data
    pub node: SocketAddr,
    /// The id of the `peer` if available
    pub peer_id: Option<IdBytes>,
    /// List of peers that announced the topic hash
    pub peers: Vec<SocketAddr>,
    /// List of LAN peers that announced the topic hash
    pub local_peers: Vec<SocketAddr>,
}

/// Type to keep track of the responses for queries in progress.
#[derive(Debug)]
#[pin_project::pin_project(project = QueryStreamTypeProj)]
enum QueryStreamType {
    Lookup(LookupInner),
    Announce(AnnounceInner),
    UnAnnounce(#[pin] UnannounceInner),
    AnnounceClear(AunnounceClearInner),
    FindPeer(FindPeerInner),
}

#[derive(Debug)]
enum QueryStreamResult {
    Lookup(QueryResult),
    Announce(QueryResult),
    UnAnnounce(UnannounceResult),
    AnnounceClear(AnnounceClearResult),
    FindPeer(QueryResult),
}

impl Future for QueryStreamType {
    type Output = Result<QueryStreamResult>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use QueryStreamResult as qsr;
        use QueryStreamTypeProj as qstp;
        match self.project() {
            qstp::UnAnnounce(mut inner) => {
                if let Poll::Ready(x) = Future::poll(Pin::new(&mut inner), cx) {
                    match x {
                        Ok(res) => return Poll::Ready(Ok(qsr::UnAnnounce(res))),
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Pending
            }
            qstp::Announce(mut inner) => {
                if let Poll::Ready(x) = Future::poll(Pin::new(&mut inner), cx) {
                    match x {
                        Ok(res) => return Poll::Ready(Ok(qsr::Announce(res))),
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Pending
            }
            qstp::Lookup(mut inner) => {
                if let Poll::Ready(x) = Future::poll(Pin::new(&mut inner), cx) {
                    match x {
                        Ok(res) => return Poll::Ready(Ok(qsr::Lookup(res))),
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Pending
            }
            qstp::AnnounceClear(mut inner) => {
                if let Poll::Ready(x) = Future::poll(Pin::new(&mut inner), cx) {
                    match x {
                        Ok(res) => return Poll::Ready(Ok(qsr::AnnounceClear(res))),
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Pending
            }
            qstp::FindPeer(mut inner) => {
                if let Poll::Ready(x) = Future::poll(Pin::new(&mut inner), cx) {
                    match x {
                        Ok(res) => return Poll::Ready(Ok(qsr::FindPeer(res))),
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Pending
            }
        }
    }
}

impl QueryStreamType {
    fn commit(&mut self, query: Arc<RwLock<Query>>, mut channel: mpsc::Sender<CommitMessage>) {
        match self {
            QueryStreamType::Lookup(_) => todo!(),
            QueryStreamType::UnAnnounce(_) => todo!(),
            QueryStreamType::Announce(inner) => {
                let q = query.read().unwrap();
                // TODO UGLY
                warn!("# closest replies = [{}]", q.closest_replies.len());
                for cr in q.closest_replies.iter() {
                    let Some(pid) = cr.request.to.id else {
                        // refactor this to be handled in the type system
                        warn!("closest_replies peer without id.. Should not happen");
                        continue;
                    };
                    trace!(
                        "Sending commit to peer.id = [{:?}]",
                        Into::<IdBytes>::into(pid)
                    );
                    channel
                        .try_send(CommitMessage::Send(CommitRequestParams {
                            command: commands::ANNOUNCE,
                            target: Some(inner.topic),
                            value: Some(request_announce_or_unannounce_value(
                                &inner.keypair,
                                inner.topic,
                                &cr.response.token.expect("todo"),
                                pid.into(),
                                &[],
                                &crate::crypto::namespace::ANNOUNCE,
                            )),
                            peer: cr.peer.addr,
                            query_id: q.id,
                            token: cr.response.token.expect("TODO"),
                        }))
                        .expect("TODO");
                }

                debug!("Emit CommitMessage::Done for query.id = {}", q.id);
                channel.try_send(CommitMessage::Done).unwrap();
            }
            QueryStreamType::AnnounceClear(_) => todo!(),
            QueryStreamType::FindPeer(_inner) => todo!(),
        }
    }

    fn target_search_done(&mut self, msg_tx: MessageSender, query_result: RpcQueryResult) {
        match self {
            QueryStreamType::Lookup(ref mut inner) => inner.finalize(),
            QueryStreamType::Announce(ref mut inner) => inner.finalize(),
            QueryStreamType::UnAnnounce(ref mut inner) => inner.finalize(),
            QueryStreamType::AnnounceClear(ref mut inner) => inner.finalize(msg_tx, query_result),
            QueryStreamType::FindPeer(ref mut inner) => inner.finalize(),
        }
    }
}

pub fn request_announce_or_unannounce_value(
    keypair: &Keypair,
    target: IdBytes,
    token: &[u8; 32],
    from: IdBytes,
    relay_addresses: &[SocketAddr],
    namespace: &[u8; 32],
) -> Vec<u8> {
    let announce =
        sign_announce_or_unannounce(keypair, target, token, &from.0, relay_addresses, namespace);
    announce
        .to_encoded_bytes()
        .expect("known to succeed for all `Announce` values")
        .to_vec()
}
