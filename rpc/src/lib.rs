//! Rust Implementation of the hyperswarm DHT
#![deny(clippy::enum_glob_use)]
#![warn(rust_2018_idioms)]
#![allow(unreachable_code)]

pub mod cenc;
pub mod commit;
pub mod constants;
mod futreqs;
pub mod io;
mod jobs;
pub mod kbucket;
mod message;
pub mod peers;
pub mod query;
mod stateobserver;
mod stream;
mod util;

pub use futreqs::{new_request_channel, Error as RequestFutureError, RequestFuture};

#[cfg(test)]
mod s_test;
#[cfg(test)]
pub mod test;
use constants::ID_BYTES_LENGTH;
use futures::{channel::mpsc, Stream};
use query::{CommandQueryResponse, QueryResult};
use std::{
    array::TryFromSliceError,
    borrow::Borrow,
    collections::{BTreeSet, HashSet, VecDeque},
    convert::{TryFrom, TryInto},
    fmt::Display,
    iter::FromIterator,
    net::{AddrParseError, SocketAddr, ToSocketAddrs},
    pin::Pin,
    str::FromStr,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Duration,
};
use tracing::{debug, error, instrument, trace, warn};
use wasm_timer::Instant;

use rand::{
    rngs::{OsRng, StdRng},
    RngCore, SeedableRng,
};

use crate::{
    cenc::{generic_hash, validate_id},
    commit::{Commit, CommitMessage, Progress},
    io::InResponse,
    jobs::PeriodicJob,
    kbucket::{distance, Distance},
    kbucket::{Entry, EntryView, InsertResult, KBucketsTable, NodeStatus, K_VALUE},
    query::QueryId,
    util::pretty_bytes,
};
use compact_encoding::EncodingError;
use tokio::sync::oneshot::error::RecvError;

pub use self::message::{ReplyMsgData, RequestMsgData, RequestMsgDataInner};
use self::{
    io::{IoConfig, IoHandler, IoHandlerEvent},
    query::{
        table::PeerState, CommandQuery, Query, QueryConfig, QueryEvent, QueryPool, QueryPoolEvent,
        QueryStats,
    },
    stateobserver::State,
    stream::MessageDataStream,
};
pub use crate::io::Tid;

/// The publicly available hyperswarm DHT addresses
pub const DEFAULT_BOOTSTRAP: [&str; 3] = [
    "node1.hyperdht.org:49737",
    "node2.hyperdht.org:49737",
    "node3.hyperdht.org:49737",
];

/// The command identifier for `Mutable` storage
pub const MUTABLE_STORE_CMD: usize = 1;
/// The command identifier for immutable storage
pub const IMMUTABLE_STORE_CMD: usize = 2;
/// The command identifier to (un)announce/lookup peers
pub const PEERS_CMD: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
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
    #[error("Request failed with: {0}")]
    RequestFailed(#[from] RequestFutureError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// TODO make EncodingError impl Error trait
impl From<EncodingError> for Error {
    fn from(value: EncodingError) -> Self {
        Error::CompactEncodingError(value)
    }
}

/// TODO in js this is de/encoded with c.uint which is for a variable sized unsigned integer.
// but it is always one byte. We use a u8 instead of a usize here. So there is a limit on 256
// commands.
#[derive(Copy, Debug, Clone, PartialEq)]
#[repr(u8)]
pub enum InternalCommand {
    Ping = 0,
    PingNat,
    FindNode,
    DownHint,
}

impl Display for InternalCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalCommand as Ic;
        write!(f, "COMMAND")?;
        match self {
            Ic::Ping => write!(f, "::Ping"),
            Ic::PingNat => write!(f, "::PingNat"),
            Ic::FindNode => write!(f, "::FindNode"),
            Ic::DownHint => write!(f, "::DownHint"),
        }
    }
}

impl From<InternalCommand> for Command {
    fn from(value: InternalCommand) -> Self {
        Command::Internal(value)
    }
}

#[derive(Copy, Debug, Clone, PartialEq)]
pub struct ExternalCommand(pub usize);

/// TODO This is encoded as u8 which might not always be true
#[derive(Copy, Debug, Clone, PartialEq)]
pub enum Command {
    Internal(InternalCommand),
    External(ExternalCommand),
}

impl Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Internal(c) => write!(f, "Internal({})", c),
            Command::External(ExternalCommand(x)) => {
                let cmd_name = match x {
                    0 => "PEER_HANDSHAKE",
                    1 => "PEER_HOLEPUNCH",
                    2 => "FIND_PEER",
                    3 => "LOOKUP",
                    4 => "ANNOUNCE",
                    5 => "UNANNOUNCE",
                    mystery => &format!("??{mystery}??"),
                };
                write!(f, "External({cmd_name})")
            }
        }
    }
}

impl Command {
    fn encode(&self) -> u8 {
        match &self {
            Command::Internal(cmd) => *cmd as u8,
            Command::External(ExternalCommand(cmd)) => *cmd as u8,
        }
    }
}

impl TryFrom<u8> for InternalCommand {
    type Error = crate::Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        use InternalCommand as Ic;
        Ok(match value {
            0 => Ic::Ping,
            1 => Ic::PingNat,
            2 => Ic::FindNode,
            3 => Ic::DownHint,
            x => return Err(crate::Error::InvalidRpcCommand(x)),
        })
    }
}

fn thirty_two_random_bytes() -> [u8; 32] {
    let mut buff = [0; 32];
    let mut rng = StdRng::from_rng(OsRng).unwrap();
    rng.fill_bytes(&mut buff);
    buff
}

pub(crate) type QueryAndTid = (Option<QueryId>, Tid);

#[derive(Debug, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct RpcDht {
    // TODO use message passing to update id's in IoHandler
    #[builder(default = "State::new(IdBytes::from(thirty_two_random_bytes()))")]
    pub id: State<IdBytes>,
    ephemeral: bool,
    pub(crate) kbuckets: KBucketsTable<Node>,
    pub io: IoHandler,
    bootstrap_job: PeriodicJob,
    ping_job: PeriodicJob,
    /// The currently active (i.e. in-progress) queries.
    queries: QueryPool,
    /// Custom commands
    #[allow(unused)] // TODO FIXME
    commands: HashSet<usize>,
    /// Queued events to return when being polled.
    queued_events: VecDeque<RpcDhtEvent>,
    #[builder(field(ty = "Vec<SocketAddr>"))]
    bootstrap_nodes: Vec<SocketAddr>,
    bootstrapped: bool,
    down_hints_in_progress: Vec<(u16, IdBytes, Instant)>,
}

#[derive(Debug)]
pub struct DhtConfig {
    pub kbucket_pending_timeout: Duration,
    pub local_id: Option<[u8; 32]>,
    pub commands: HashSet<usize>,
    pub query_config: QueryConfig,
    pub io_config: IoConfig,
    pub bootstrap_interval: Duration,
    pub ping_interval: Duration,
    #[allow(unused)] // FIXME bg: why never read?
    pub connection_idle_timeout: Duration,
    pub ephemeral: bool,
    pub adaptive: bool,
    pub bootstrap_nodes: Vec<SocketAddr>,
    pub socket: Option<MessageDataStream>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        DhtConfig {
            kbucket_pending_timeout: Duration::from_secs(60),
            local_id: None,
            commands: Default::default(),
            query_config: Default::default(),
            ping_interval: Duration::from_secs(40),
            bootstrap_interval: Duration::from_secs(320),
            connection_idle_timeout: Duration::from_secs(10),
            ephemeral: false,
            adaptive: false,
            bootstrap_nodes: Vec::new(),
            socket: None,
            io_config: Default::default(),
        }
    }
}

impl DhtConfig {
    /// Create a new UDP socket and attempt to bind it to the addr provided.
    pub fn bind<A: ToSocketAddrs>(mut self, addr: A) -> crate::Result<Self> {
        self.socket = Some(MessageDataStream::bind(addr)?);
        Ok(self)
    }
    pub fn add_bootstrap_node<A: Into<SocketAddr>>(mut self, addr: A) -> Self {
        self.bootstrap_nodes.push(addr.into());
        self
    }
    pub fn empty_bootstrap_nodes(mut self) -> Self {
        self.bootstrap_nodes = vec![];
        self
    }
    /// Set the nodes to bootstrap from
    pub fn set_bootstrap_nodes<T: ToSocketAddrs>(mut self, addresses: &[T]) -> Self {
        let mut bootstrap_nodes = vec![];

        for addrs in addresses {
            if let Ok(addrs) = addrs.to_socket_addrs() {
                for addr in addrs {
                    bootstrap_nodes.push(addr)
                }
            }
        }
        self.bootstrap_nodes = bootstrap_nodes;
        self
    }

    /// Register all commands to listen to.
    pub fn register_commands(mut self, cmds: &[usize]) -> Self {
        for cmd in cmds {
            self.commands.insert(*cmd);
        }
        self
    }

    /// Set ephemeral: true so other peers do not add us to the peer list,
    /// simply bootstrap.
    ///
    /// An ephemeral dht node won't expose its id to remote peers, hence being
    /// ignored.
    pub fn ephemeral(mut self) -> Self {
        self.ephemeral = true;
        self
    }

    pub fn set_ephemeral(mut self, ephemeral: bool) -> Self {
        self.ephemeral = ephemeral;
        self
    }
}

impl RpcDht {
    pub async fn with_config(config: DhtConfig) -> crate::Result<Self> {
        let bites = config.local_id.unwrap_or_else(thirty_two_random_bytes);
        let id_bytes = IdBytes::from(bites);
        let local_id = id_bytes;
        let id = State::new(local_id);

        let socket = config
            .socket
            .map(Result::Ok)
            .unwrap_or_else(MessageDataStream::defualt_bind)?;

        let io = IoHandler::new(id.view(), socket, config.io_config);

        let mut dht = Self {
            id,
            ephemeral: config.ephemeral,
            kbuckets: KBucketsTable::new(local_id, config.kbucket_pending_timeout),
            io,
            bootstrap_job: PeriodicJob::new(config.bootstrap_interval),
            ping_job: PeriodicJob::new(config.ping_interval),
            queries: QueryPool::new(local_id, config.query_config),
            commands: config.commands,
            queued_events: Default::default(),
            bootstrap_nodes: config.bootstrap_nodes,
            bootstrapped: false,
            down_hints_in_progress: Vec::new(),
        };

        dht.bootstrap();
        Ok(dht)
    }

    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Returns the local address that this listener is bound to.
    pub fn local_addr(&self) -> crate::Result<SocketAddr> {
        self.io.local_addr()
    }
    /// Returns the id used to identify this node.
    pub fn local_id(&self) -> &IdBytes {
        self.id.get_ref()
    }

    pub fn bootstrap(&mut self) {
        if !self.bootstrap_nodes.is_empty() {
            let target = self.id.get();
            let peers = self
                .kbuckets
                .closest(&target)
                .take(usize::from(K_VALUE))
                .map(|e| PeerId::new(e.node.value.addr, e.node.key))
                .collect::<Vec<_>>();
            let bootstrap_nodes: Vec<Peer> = self.bootstrap_nodes.iter().map(Peer::from).collect();
            self.queries.bootstrap(target, peers, bootstrap_nodes);
        } else if !self.bootstrapped {
            self.queued_events.push_back(RpcDhtEvent::Bootstrapped {
                stats: QueryStats::empty(),
            });
            self.bootstrapped = true;
        }
    }

    pub fn is_bootstrapped(&self) -> bool {
        self.bootstrapped
    }

    #[instrument(skip(self, value))]
    pub fn query(
        &mut self,
        cmd: Command,
        target: IdBytes,
        value: Option<Vec<u8>>,
        commit: Commit,
    ) -> QueryId {
        self.run_command(cmd, target, value, commit)
    }

    #[instrument(skip(self))]
    fn run_command(
        &mut self,
        cmd: Command,
        target: IdBytes,
        value: Option<Vec<u8>>,
        commit: Commit,
    ) -> QueryId {
        let peers = self
            .kbuckets
            .closest(&target)
            .take(usize::from(K_VALUE))
            .map(|e| PeerId::new(e.node.value.addr, e.node.key))
            .collect::<Vec<_>>();

        let bootstrap_nodes: Vec<Peer> = self.bootstrap_nodes.iter().map(Peer::from).collect();
        self.queries
            .add_stream(cmd, peers, target, value, bootstrap_nodes, commit)
    }

    pub fn request(
        &mut self,
        command: Command,
        target: Option<IdBytes>,
        value: Option<Vec<u8>>,
        destination: Peer,
        token: Option<[u8; 32]>,
    ) -> Tid {
        self.io
            .request(command, target, value, destination, None, token)
            .1
    }

    pub fn ping(&mut self, peer: &Peer) -> QueryAndTid {
        self.io.request(
            Command::Internal(InternalCommand::Ping),
            None,
            None,
            peer.clone(),
            None,
            None,
        )
    }

    fn ping_some(&mut self) -> Vec<QueryAndTid> {
        let cnt = if self.queries.len() > 2 { 3 } else { 5 };
        let now = Instant::now();
        let mut out = vec![];
        let ping_interval = self.ping_job.interval;
        for peer in self
            .kbuckets
            .iter()
            .filter_map(|entry| {
                if now > entry.node.value.last_seen + ping_interval {
                    Some(Peer::from(entry.node.value.addr))
                } else {
                    None
                }
            })
            .take(cnt)
            .collect::<Vec<_>>()
        {
            out.push(self.ping(&peer));
        }
        out
    }

    /// Handle the event generated from the underlying IO
    fn inject_event(&mut self, event: IoHandlerEvent) {
        match event {
            IoHandlerEvent::OutResponse { .. } => {}
            IoHandlerEvent::OutSocketErr { .. } => {}
            IoHandlerEvent::InRequest { message, peer } => {
                self.on_request(message, peer);
            }
            IoHandlerEvent::InMessageErr { .. } => {}
            IoHandlerEvent::InSocketErr { .. } => {}
            IoHandlerEvent::InResponseBadRequestId { .. } => {
                // received a response that did not match any issued requests
                //self.remove_node(&peer);
                todo!()
            }
            IoHandlerEvent::OutRequest { .. } => {
                // sent a request
            }
            IoHandlerEvent::InResponse(resp) => {
                self.on_response(resp);
            }
            IoHandlerEvent::RequestTimeout { .. } => {
                todo!()
            }
            IoHandlerEvent::ChanneledResponse(tid) => {
                trace!(msg.id = tid, "Passed io response through channel")
            }
        }
    }

    /// Process a response.
    fn on_response(&mut self, resp_data: Arc<InResponse>) {
        if let Some(id) = validate_id(&resp_data.response.id, &resp_data.peer) {
            self.add_node(
                id,
                resp_data.peer.clone(),
                None,
                Some(SocketAddr::from(&resp_data.response.to)),
            );
        }
        match resp_data.query_id {
            Some(query_id) => {
                if let Some(query) = self.queries.get(&query_id) {
                    if let Some(resp) = query.write().unwrap().inject_response(resp_data) {
                        self.queued_events
                            .push_back(RpcDhtEvent::ResponseResult(Ok(ResponseOk::Response(resp))))
                    }
                } else {
                    debug!("Recieved response for missing query with id: {:?}. It could have been removed already", resp_data.query_id);
                }
            }
            None => {
                if matches!(
                    resp_data.request.command,
                    Command::Internal(InternalCommand::Ping)
                ) {
                    if resp_data.query_id.is_some() {
                        error!("Ping has a QueryId?");
                    }
                    self.on_pong(&resp_data.response, resp_data.peer.clone());
                    return;
                }
                panic!("TODO");
            }
        }
    }

    /// Handle an incoming request.
    ///
    /// Eventually send a response.
    fn on_request(&mut self, msg: RequestMsgData, peer: Peer) {
        if let Some(id) = validate_id(&msg.id, &peer) {
            self.add_node(id, peer.clone(), None, Some(SocketAddr::from(&msg.to)));
        }

        match msg.command {
            Command::Internal(cmd) => match cmd {
                InternalCommand::Ping => self.on_ping(msg, &peer),
                InternalCommand::FindNode => self.on_find_node(msg, peer),
                InternalCommand::PingNat => self.on_ping_nat(msg, peer),
                InternalCommand::DownHint => self.on_down_hint(msg, peer),
            },
            Command::External(_cmd) => todo!(),
        }
    }

    fn add_node(
        &mut self,
        id: IdBytes,
        peer: Peer,
        roundtrip_token: Option<Vec<u8>>,
        to: Option<SocketAddr>,
    ) {
        match self.kbuckets.entry(&id) {
            Entry::Present(mut entry, _) => {
                entry.value().last_seen = Instant::now();
            }
            Entry::Pending(mut entry, _) => {
                let n = entry.value();
                n.addr = peer.addr;
                n.last_seen = Instant::now();
            }
            Entry::Absent(entry) => {
                let node = Node {
                    addr: peer.addr,
                    roundtrip_token,
                    to,
                    last_seen: Instant::now(),
                    referrers: vec![],
                    down_hint: false,
                    last_pinged: None,
                };

                use InsertResult as Ir;
                match entry.insert(node, NodeStatus::Connected) {
                    Ir::Inserted => {
                        self.queued_events.push_back(RpcDhtEvent::RoutingUpdated {
                            peer,
                            old_peer: None,
                        });
                    }
                    Ir::Full => {
                        debug!("Bucket full. Peer not added to routing table: {:?}", peer)
                    }
                    Ir::Pending { disconnected: _ } => {

                        // TODO dial remote
                    }
                }
            }
            Entry::SelfEntry => {}
        }
    }
    pub fn reply_command(&mut self, resp: CommandQueryResponse) {
        self.io.reply(resp.msg)
    }

    #[allow(unused)] // TODO FIXME
    fn reply(
        &mut self,
        error: usize,
        value: Option<Vec<u8>>,
        token: Option<[u8; 32]>,
        has_closer_nodes: bool,
        request: RequestMsgData,
        peer: &Peer,
    ) {
        let closer_nodes: Vec<Peer> = match (has_closer_nodes, request.target) {
            (true, Some(key)) => self.closer_nodes(IdBytes::from(key), usize::from(K_VALUE)),
            _ => vec![],
        };
        let msg = ReplyMsgData {
            tid: request.tid,
            to: peer.clone(),
            id: None,
            token,
            closer_nodes,
            error,
            value,
        };
        self.io.reply(msg)
    }

    /// Handle a ping request
    fn on_ping(&mut self, msg: RequestMsgData, peer: &Peer /* peer who sent ping */) {
        let msg = ReplyMsgData {
            tid: msg.tid,
            to: peer.clone(),
            id: (!self.ephemeral).then(|| self.id.get().0),
            token: self.io.token(peer, 1).ok(),
            closer_nodes: vec![],
            error: 0,
            value: None,
        };
        self.io.reply(msg)
    }

    /// Handle an incoming find peers request.
    ///
    /// Reply only if the remote provided a target to get the closest nodes for.
    fn on_find_node(&mut self, request: RequestMsgData, peer: Peer) {
        // TODO same as 582
        let closer_nodes: Vec<Peer> = match request.target {
            Some(t) => self.closer_nodes(IdBytes::from(t), usize::from(K_VALUE)),
            None => {
                // TODO emit an event about this
                warn!("Got FIND_NODE without a target. Msg: {request:?}");
                return;
            }
        };
        self.io.reply(ReplyMsgData {
            tid: request.tid,
            to: peer.clone(),
            id: (!self.ephemeral).then(|| self.id.get().0),
            token: self.io.token(&peer, 1).ok(),
            closer_nodes,
            error: 0,
            value: None,
        });
    }

    /// Get the `num` closest nodes in the bucket.
    fn closer_nodes(&mut self, key: IdBytes, num: usize) -> Vec<Peer> {
        let nodes = self
            .kbuckets
            .closest(&key)
            .take(num)
            .map(|p| Peer::from(&p.node.value.addr))
            .collect::<Vec<_>>();
        nodes
        //PeersEncoding::encode(&nodes)
    }
    fn on_down_hint(&mut self, request: RequestMsgData, peer: Peer) {
        match &request.value {
            None => {
                // TODO emit an event about this
                warn!("Got DOWN_HINT with no value. Msg: {request:?}");
            }
            Some(value) => {
                if value.len() < 6 {
                    // TODO emit an event about this
                    warn!("Got DOWN_HINT with value too small. Msg: {request:?}");
                    return;
                }
                if self.down_hints_in_progress.len() < 10 {
                    let key = IdBytes::from(generic_hash(&value[..6]));
                    // NB: akwardness follows.
                    // We have to mutate some state to track the DownHint progress. but doing this
                    // is split up between outside and inside the match statement
                    //
                    // this happenes bc we take a mutable borrow of `self` entering the
                    // match statement. but in Pending/Present we want to mutate self in order
                    // track state related to DownHint. In these cases we return node.addr from the
                    // match, and use then do our self mutation.
                    //
                    // we can't return the node from the match because it's a reference.

                    // why a macro? we can't use a function because we can't take an immutable
                    // borrow of self to pass to the func
                    macro_rules! update_node_for_down_hint {
                        ($entry:tt) => {{
                            let node = $entry.value();
                            if node.pinged_within_last(Duration::from_millis(
                                crate::constants::TICK_INTERVAL_MS,
                            )) || !node.down_hint
                            {
                                node.down_hint = true;
                                node.ping_sent();
                                (node.addr, node.last_seen)
                            } else {
                                warn!(
                                    "Got DOWN_HINT for node already DOWN_HINT'd. Msg: {request:?}"
                                );
                                return;
                            }
                        }};
                    }

                    let (node_addr, last_seen) = match self.kbuckets.entry(&key) {
                        Entry::Pending(mut entry, _) => {
                            update_node_for_down_hint!(entry)
                        }
                        Entry::Present(mut entry, _) => {
                            update_node_for_down_hint!(entry)
                        }
                        _ => {
                            warn!("Got DOWN_HINT for node we don't have. Msg: {request:?}");
                            return;
                        }
                    };
                    // update self for down hint
                    let (_, tid) = self.ping(&Peer::from(node_addr));
                    self.down_hints_in_progress.push((tid, key, last_seen));
                }
                self.io.reply(ReplyMsgData {
                    tid: request.tid,
                    token: self.io.token(&peer, 1).ok(),
                    to: peer,
                    id: (!self.ephemeral).then(|| self.id.get().0),
                    closer_nodes: vec![],
                    error: 0,
                    value: None,
                })
            }
        };
    }

    fn on_ping_nat(&mut self, request: RequestMsgData, mut peer: Peer) {
        let port = match &request.value {
            Some(port_buf) => {
                if port_buf.len() < 2 {
                    // TODO emit an event about this
                    warn!("Got PING_NAT with value too small. Msg: {request:?}");
                    return;
                }
                let port = u16::from_le_bytes([port_buf[0], port_buf[1]]);
                if port == 0 {
                    warn!("Got PING_NAT with port == 0. Msg: {request:?}");
                    return;
                }
                port
            }
            None => {
                // TODO emit an event about this
                warn!("Got PING_NAT without a value. Msg: {request:?}");
                return;
            }
        };
        peer.addr.set_port(port);
        let token = self.io.token(&peer, 1).ok();
        self.io.reply(ReplyMsgData {
            tid: request.tid,
            to: peer,
            id: (!self.ephemeral).then(|| self.id.get().0),
            token,
            closer_nodes: vec![],
            error: 0,
            value: None,
        });
    }
    /// Handle a response for our Ping command
    fn on_pong(&mut self, msg: &ReplyMsgData, peer: Peer) {
        // check if pong was for a downhint ping
        if let Some(pos) = self
            .down_hints_in_progress
            .iter()
            .position(|&(tid, _, _)| tid == msg.tid)
        {
            let (_, key, last_seen) = self.down_hints_in_progress.remove(pos);
            if msg.error != 0 {
                self.remove_peer(&key);
            } else {
                // we received a good response from an address than was downhinted.
                // the node either isn't down, or it is a new node (with a new id)
                // if it isn't down, node.last_seen is already updated because we have
                // already called add_node on this message. otherwise last_seen
                // is the same as it was we we pinged the node
                self.remove_stale_peer(&key, last_seen);
            }
        }

        self.queued_events
            .push_back(RpcDhtEvent::ResponseResult(Ok(ResponseOk::Pong(peer))));
    }

    fn default_commit(&mut self, query: Arc<RwLock<Query>>) -> Vec<Tid> {
        let q = query.read().unwrap();
        q.closest_replies
            .iter()
            .map(|rep| {
                self.io
                    .request(
                        q.cmd,
                        Some(q.peer_iter.target),
                        q.value.clone(),
                        rep.peer.clone(),
                        Some(q.id),
                        rep.response.token,
                    )
                    .1
            })
            .collect()
    }

    /// Delegate new query event to the io handler
    fn inject_query_event(&mut self, id: QueryId, event: QueryEvent) {
        match event {
            QueryEvent::Query {
                peer,
                command,
                target,
                value,
            } => {
                self.io
                    .request(command, Some(target), value, peer, Some(id), None);
            }
            QueryEvent::RemoveNode { id } => {
                self.remove_peer(&id);
            }
            QueryEvent::MissingRoundtripToken { .. } => {
                // TODO
            }
            _ => {
                todo!()
            } /*
              QueryEvent::Update {
                  peer,
                  command,
                  target,
                  value,
                  token,
              } => {
                  self.io
                      .update(command, Some(target), value, peer, token, id);
              }
              */
        }
    }

    /// Removes a peer from the routing table.
    ///
    /// Returns `None` if the peer was not in the routing table,
    /// not even pending insertion.
    pub fn remove_peer(&mut self, key: &IdBytes) -> Option<EntryView<Node>> {
        match self.kbuckets.entry(key) {
            Entry::Present(entry, _) => Some(entry.remove()),
            Entry::Pending(entry, _) => Some(entry.remove()),
            Entry::Absent(..) | Entry::SelfEntry => None,
        }
    }
    pub fn remove_stale_peer(
        &mut self,
        key: &IdBytes,
        last_seen: Instant,
    ) -> Option<EntryView<Node>> {
        match self.kbuckets.entry(key) {
            Entry::Present(mut entry, _) => {
                if entry.value().last_seen <= last_seen {
                    return Some(entry.remove());
                }
                None
            }
            Entry::Pending(mut entry, _) => {
                if entry.value().last_seen <= last_seen {
                    return Some(entry.remove());
                };
                None
            }
            Entry::Absent(..) | Entry::SelfEntry => None,
        }
    }

    /// Handles a finished query.
    #[instrument(skip_all)]
    fn query_finished(&mut self, query: Arc<RwLock<Query>>) -> RpcDhtEvent {
        let is_find_node = matches!(
            query.read().unwrap().command(),
            Command::Internal(InternalCommand::FindNode)
        );

        let result = query.read().unwrap().into_result();

        // add nodes to the table
        for (peer, state) in result.peers.iter() {
            match state {
                PeerState::Failed => {
                    debug!("peer.id = [{:?}] Failed - removing", peer.id);
                    self.remove_peer(&peer.id);
                }
                PeerState::Succeeded {
                    roundtrip_token,
                    to,
                } => {
                    debug!("peer.id = [{:?}] Succeeded", peer.id);
                    self.add_node(
                        peer.id,
                        Peer::from(peer.addr),
                        Some(roundtrip_token.clone()),
                        *to,
                    );
                }
                PeerState::NotContacted => {
                    trace!("peer.id = [{:?}] NotContacted", peer.id);
                }
            }
        }

        // first `find_node` query is issued as bootstrap
        if is_find_node && !self.bootstrapped {
            debug!("Bootstrap process's FindNode query finished");
            self.bootstrapped = true;
            RpcDhtEvent::Bootstrapped {
                stats: result.stats,
            }
        } else {
            debug!(
                cmd = tracing::field::display(result.cmd),
                "Query result ready"
            );
            RpcDhtEvent::QueryResult(result)
        }
    }
    /// Handles a query that timed out.
    fn query_timeout(&mut self, query: Arc<RwLock<Query>>) -> RpcDhtEvent {
        self.query_finished(query)
    }

    pub fn new_tid(&self) -> Tid {
        self.io.new_tid()
    }
    pub fn id(&self) -> IdBytes {
        self.io.id()
    }
    pub fn send_request(&mut self, msg: (Option<QueryId>, RequestMsgData)) {
        self.io.enqueue_request(msg)
    }
}
#[derive(Debug)]
pub enum RpcDhtEvent {
    /// Result wrapping an incomming Request
    /// Only emits Ok on custom commands. Errs on any request error (custom or non-custom)
    RequestResult(RequestResult),
    /// Result wrapping an incomming Response
    /// Emits for any valid response
    ResponseResult(ResponseResult),
    /// The routing table has been updated.
    RoutingUpdated {
        /// The ID of the peer that was added or updated.
        peer: Peer,
        /// The ID of the peer that was evicted from the routing table to make
        /// room for the new peer, if any.
        old_peer: Option<Peer>,
    },
    Bootstrapped {
        /// Execution statistics from the bootstrap query.
        stats: QueryStats,
    },

    /// Only emitted when Query is made with Commit::Custom
    ReadyToCommit {
        /// The query we are commiting for
        query: Arc<RwLock<Query>>,
        tx_commit_messages: mpsc::Sender<CommitMessage>,
    },
    /// A completed query.
    ///
    /// No more responses are expected for this query
    QueryResult(QueryResult),
}

pub type RequestResult = std::result::Result<RequestOk, RequestError>;

#[derive(Debug)]
pub enum RequestOk {
    /// Custom incoming request to a registered command
    ///
    /// # Note
    ///
    /// Custom commands are not automatically replied to and need to be answered
    /// manually
    CustomCommandRequest {
        /// The query we received and need to respond to
        query: CommandQuery,
        request: Box<RequestMsgData>,
        peer: Peer, // maybe peerid? or SocketAddr
    },
}

#[derive(Debug)]
pub enum RequestError {
    /// Received a query with a custom command that is not registered
    UnsupportedCommand {
        /// The unknown command
        command: String,
        /// The message we received from the peer.
        msg: RequestMsgData,
        /// The peer the message originated from.
        peer: Peer,
    },
    /// The `target` field of message was required but was empty
    MissingTarget { msg: RequestMsgData, peer: Peer },
    /// Received a message with a type other than [`Type::Query`],
    /// [`Type::Response`], [`Type::Update`]
    InvalidType {
        ty: i32,
        msg: RequestMsgData,
        peer: Peer,
    },
    /// Received a request with no command attached.
    MissingCommand { peer: Peer },
    /// Ignored Request due to message's value being this peer's id.
    InvalidValue { msg: RequestMsgData, peer: Peer },
}

pub type ResponseResult = std::result::Result<ResponseOk, ResponseError>;

#[derive(Debug)]
pub enum ResponseOk {
    /// Received a pong response to our ping request.
    Pong(Peer),
    /// A remote peer successfully responded to our query
    Response(Arc<InResponse>),
}

#[derive(Debug)]
pub enum ResponseError {
    /// We received a bad pong to our ping request
    InvalidPong(Peer),
}

impl Stream for RpcDht {
    type Item = RpcDhtEvent;

    #[instrument(skip_all)]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        let now = Instant::now();

        if let Poll::Ready(()) = pin.bootstrap_job.poll(cx, now) {
            if pin.kbuckets.iter().count() < 20 {
                debug!("next bootstrap_job running");
                pin.bootstrap();
            }
        }

        if let Poll::Ready(()) = pin.ping_job.poll(cx, now) {
            pin.ping_some();
        }
        loop {
            // Drain queued events first.
            if let Some(event) = pin.queued_events.pop_front() {
                trace!("{event:#?}");
                return Poll::Ready(Some(event));
            }

            // Look for a sent/received message
            loop {
                if let Poll::Ready(Some(event)) = Stream::poll_next(Pin::new(&mut pin.io), cx) {
                    debug!("RpcDht got IoHandlerEvent::{event}");
                    pin.inject_event(event);
                    if let Some(event) = pin.queued_events.pop_front() {
                        trace!("emit queue event: {event:?}");
                        return Poll::Ready(Some(event));
                    }
                } else {
                    match pin.queries.poll(now) {
                        QueryPoolEvent::Commit((query, cev)) => {
                            use commit::{Commit as C, CommitEvent as E, Progress as P};
                            // TODO add all commit handlers
                            match cev {
                                E::AutoStart((_, _)) => {
                                    let tids = pin.default_commit(query.clone());
                                    query.write().unwrap().commit =
                                        C::Auto(P::AwaitingReplies(BTreeSet::from_iter(tids)))
                                }
                                E::CustomStart((tx_commit_messages, _)) => {
                                    return Poll::Ready(Some(RpcDhtEvent::ReadyToCommit {
                                        query,
                                        tx_commit_messages,
                                    }));
                                }
                                E::SendRequests((commits, _)) => {
                                    for msg in commits {
                                        match msg {
                                            CommitMessage::Send(cr) => {
                                                let (_, tid) = pin.io.request(
                                                    cr.command,
                                                    cr.target,
                                                    cr.value,
                                                    cr.peer.into(),
                                                    Some(cr.query_id),
                                                    Some(cr.token),
                                                );
                                                if let C::Custom(prog @ P::Sending(_)) =
                                                    &mut query.write().unwrap().commit
                                                {
                                                    prog.sent_tid(tid);
                                                }
                                            }
                                            CommitMessage::Done => {
                                                match &mut query.write().unwrap().commit {
                                                    C::Custom(prog @ P::Sending(_)) => {
                                                        // Done should only be emitted last. Any
                                                        // further rquests sent with `Send` are
                                                        // dropped
                                                        prog.transition_to_awaiting();
                                                        if prog.all_replies_recieved() {
                                                            // if we'd already recieved all replies,
                                                            // we're done
                                                            *prog = Progress::Done;
                                                        }
                                                    }
                                                    _ => {
                                                        // We expect that only `Custom` sends
                                                        // SendRequests. and only sends Done while
                                                        // in `Sending`
                                                        todo!()
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                E::Done => {
                                    todo!("Commit Done!")
                                }
                            }
                        }
                        QueryPoolEvent::Waiting(Some((query, event))) => {
                            let id = query.read().unwrap().id();
                            pin.inject_query_event(id, event);
                        }
                        QueryPoolEvent::Finished(q) => {
                            trace!(
                                "QueryPoolEvent::Finished. Query::id = {:?}",
                                q.try_read().map(|x| x.id)
                            );
                            let event = pin.query_finished(q);
                            return Poll::Ready(Some(event));
                        }
                        QueryPoolEvent::Timeout(q) => {
                            let event = pin.query_timeout(q);
                            trace!("{event:#?}");
                            return Poll::Ready(Some(event));
                        }
                        QueryPoolEvent::Waiting(None) | QueryPoolEvent::Idle => {
                            break;
                        }
                    }
                }
            }

            // No immediate event was produced as a result of a finished query or socket.
            // If no new events have been queued either, signal `Pending` to
            // be polled again later.
            if pin.queued_events.is_empty() {
                return Poll::Pending;
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Peer {
    pub id: Option<[u8; 32]>,
    pub addr: SocketAddr,
    /// Referrer that told us about this node.
    pub referrer: Option<SocketAddr>,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("Peer");
        if let Some(bytes) = &self.id {
            debug_struct.field("id", &format_args!("Some({})", pretty_bytes(bytes)));
        }
        if self.referrer.is_some() {
            debug_struct.field("referrer", &self.referrer);
        }
        debug_struct.field("addr", &self.addr).finish()
    }
}

impl FromStr for Peer {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let addr: SocketAddr = s.parse()?;
        Ok(Peer {
            addr,
            id: None,
            referrer: None,
        })
    }
}

// TODO DRY
impl From<&SocketAddr> for Peer {
    fn from(value: &SocketAddr) -> Self {
        Peer {
            id: None,
            addr: *value,
            referrer: None,
        }
    }
}
impl From<&Peer> for SocketAddr {
    fn from(value: &Peer) -> Self {
        value.addr
    }
}

impl From<SocketAddr> for Peer {
    fn from(value: SocketAddr) -> Self {
        Peer {
            id: None,
            addr: value,
            referrer: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    /// Address of the peer.
    pub addr: SocketAddr,
    /// last roundtrip token in a req/resp exchanged with the peer
    pub roundtrip_token: Option<Vec<u8>>,
    /// Decoded address of the `to` message field
    pub to: Option<SocketAddr>,
    /// When a new ping is due
    pub last_seen: Instant,
    /// Known referrers available for holepunching
    pub referrers: Vec<SocketAddr>,
    /// If this node recieved a down hint
    pub down_hint: bool,
    /// Last time a ping was sent to this node
    pub last_pinged: Option<Instant>,
}

impl Node {
    fn pinged_within_last(&self, delta: Duration) -> bool {
        if let Some(x) = self.last_pinged {
            return Instant::now().duration_since(x) > delta;
        }
        true
    }

    fn ping_sent(&mut self) {
        self.last_pinged = Some(Instant::now())
    }
}

/// A 32 byte identifier for a node participating in the DHT.
#[derive(Clone, Hash, PartialOrd, PartialEq, Eq, Copy)]
pub struct IdBytes(pub [u8; ID_BYTES_LENGTH]);

impl IdBytes {
    /// Create new 32 byte array with random bytes.
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        fill_random_bytes(&mut key);
        Self(key)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    pub fn distance(&self, other: impl AsRef<[u8]>) -> Distance {
        distance(&self.0, other.as_ref())
    }
}

impl std::fmt::Debug for IdBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdBytes({})", pretty_bytes(&self.0))
    }
}

impl Borrow<[u8]> for IdBytes {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for IdBytes {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for IdBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for IdBytes {
    type Error = std::array::TryFromSliceError;

    fn try_from(buf: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(buf.try_into()?))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PeerId {
    pub addr: SocketAddr,
    pub id: IdBytes,
}

impl PeerId {
    pub fn new(addr: SocketAddr, id: IdBytes) -> Self {
        Self { addr, id }
    }
}

impl Borrow<[u8]> for PeerId {
    fn borrow(&self) -> &[u8] {
        self.id.borrow()
    }
}

/// Fill the slice with random bytes
#[inline]
pub fn fill_random_bytes(dest: &mut [u8]) {
    use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    let mut rng = StdRng::from_rng(OsRng).unwrap();
    rng.fill_bytes(dest)
}
