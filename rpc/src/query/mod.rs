use std::{
    fmt::Display,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::Duration,
};

use closest::ClosestPeersIter;
use fnv::FnvHashMap;
use futures::{
    channel::mpsc::{self},
    task::Poll,
};
use tracing::{debug, info, instrument, trace, warn};
use wasm_timer::Instant;

use crate::{
    commit::{Commit, CommitEvent},
    constants::DEFAULT_COMMIT_CHANNEL_SIZE,
    io::InResponse,
    kbucket::{ALPHA_VALUE, K_VALUE},
    IdBytes, PeerId,
};

mod closest;
mod peers;
pub mod table;

use self::{
    peers::PeersIterState,
    table::{PeerState, QueryTable},
};
use super::{message::ReplyMsgData, Command, Peer};

/// A `QueryPool` provides an aggregate state machine for driving `Query`s to
/// completion.
#[derive(Debug)]
pub struct QueryPool {
    local_id: IdBytes,
    queries: FnvHashMap<QueryId, Arc<RwLock<Query>>>,
    config: QueryConfig,
    next_id: usize,
}

/// The configuration for queries in a `QueryPool`.
#[derive(Debug, Clone)]
pub struct QueryConfig {
    /// Timeout of a single query.
    pub timeout: Duration,

    /// The replication factor to use.
    pub replication_factor: NonZeroUsize,

    /// Allowed level of parallelism for iterative queries.
    pub parallelism: NonZeroUsize,
}

impl Default for QueryConfig {
    fn default() -> Self {
        QueryConfig {
            timeout: Duration::from_secs(60),
            replication_factor: NonZeroUsize::new(K_VALUE.get()).expect("K_VALUE > 0"),
            parallelism: ALPHA_VALUE,
        }
    }
}

impl QueryPool {
    /// Creates a new `QueryPool` with the given configuration.
    pub fn new(local_id: IdBytes, config: QueryConfig) -> Self {
        Self {
            local_id,
            next_id: 0,
            config,
            queries: Default::default(),
        }
    }

    /// Gets the current size of the pool, i.e. the number of running queries.
    pub fn len(&self) -> usize {
        self.queries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    pub(crate) fn next_query_id(&mut self) -> QueryId {
        let id = QueryId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    pub fn bootstrap(
        &mut self,
        target: IdBytes,
        peers: Vec<PeerId>,
        bootstrap: Vec<Peer>,
    ) -> QueryId {
        self.add_stream(
            Command::Internal(crate::InternalCommand::FindNode),
            peers,
            target,
            None,
            bootstrap,
            Commit::No,
        )
    }

    /// Adds a query to the pool.
    pub fn add_stream(
        &mut self,
        cmd: Command,
        peers: Vec<PeerId>,
        target: IdBytes,
        value: Option<Vec<u8>>,
        bootstrap: Vec<Peer>,
        commit: Commit,
    ) -> QueryId {
        let id = self.next_query_id();
        debug!(
            id = id.0,
            cmd = tracing::field::display(cmd),
            n_peers = peers.len(),
            n_bootstrap = bootstrap.len(),
            "new Query"
        );
        let query = Query::new(
            id,
            cmd,
            self.config.parallelism,
            self.local_id,
            target,
            value,
            peers,
            bootstrap,
            commit,
        );
        self.queries.insert(id, Arc::new(RwLock::new(query)));
        id
    }

    // Returns a reference to a query with the given ID, if it is in the pool.
    // pub fn get(&self, id: &QueryId) -> Option<&Query> {
    //     self.queries.get(id)
    // }

    /// Returns a mutable reference to a query with the given ID, if it is in
    /// the pool.
    pub fn get(&self, id: &QueryId) -> Option<Arc<RwLock<Query>>> {
        self.queries.get(id).cloned()
    }

    /// Polls the pool to advance the queries.
    #[instrument(skip_all)]
    pub fn poll(&mut self, now: Instant) -> QueryPoolEvent {
        trace!("poll for QueryPoolEvent");
        let mut finished = None;
        let mut timeout = None;
        let mut waiting = None;

        for (&query_id, query) in self.queries.iter() {
            let mut w_query = query.write().unwrap();
            w_query.stats.start = w_query.stats.start.or(Some(now));
            match w_query.poll(now) {
                Poll::Ready(Some(ev)) => {
                    match ev {
                        QueryEvent::Commit(cev) => {
                            return QueryPoolEvent::Commit((query.clone(), cev));
                        }
                        qev => waiting = Some((qev, query_id)),
                    }
                    break;
                }
                Poll::Ready(None) => {
                    finished = Some(query_id);
                    break;
                }
                Poll::Pending => {
                    let elapsed = now - w_query.stats.start.unwrap_or(now);
                    if elapsed >= self.config.timeout {
                        timeout = Some(query_id);
                        break;
                    }
                }
            }
        }

        if let Some((event, query_id)) = waiting {
            let query = self.queries.get(&query_id).expect("s.a.");
            return QueryPoolEvent::Waiting(Some((query.clone(), event)));
        }

        if let Some(query_id) = finished {
            let query = self.queries.remove(&query_id).expect("s.a.");
            query.write().unwrap().stats.end = Some(now);
            return QueryPoolEvent::Finished(query.clone());
        }

        if let Some(query_id) = timeout {
            let query = self.queries.remove(&query_id).expect("s.a.");
            query.write().unwrap().stats.end = Some(now);
            return QueryPoolEvent::Timeout(query);
        }

        if self.queries.is_empty() {
            QueryPoolEvent::Idle
        } else {
            QueryPoolEvent::Waiting(None)
        }
    }
}

/// The observable states emitted by [`QueryPool::poll`].
#[derive(Debug)]
pub enum QueryPoolEvent {
    /// The pool is idle, i.e. there are no queries to process.
    Idle,
    /// At least one query is waiting for results. `Some(request)` indicates
    /// that a new request is now being waited on.
    Waiting(Option<(Arc<RwLock<Query>>, QueryEvent)>),
    /// A query is ready to commit
    Commit((Arc<RwLock<Query>>, CommitEvent)),
    /// A query has finished.
    Finished(Arc<RwLock<Query>>),
    /// A query has timed out.
    Timeout(Arc<RwLock<Query>>),
}

#[derive(Debug)]
pub struct Query {
    /// identifier for this stream
    pub id: QueryId,
    /// The permitted parallelism, i.e. number of pending results.
    #[allow(unused)] // TODO
    parallelism: NonZeroUsize,
    /// The peer iterator that drives the query state.
    pub(crate) peer_iter: ClosestPeersIter,
    /// The rpc command of this stream
    pub cmd: Command,
    /// Stats about this query
    stats: QueryStats,
    /// The value to include in each message
    pub value: Option<Vec<u8>>,
    /// The inner query state.
    inner: QueryTable,
    /// Whether to send commits when query completes
    pub commit: Commit,
    /// Closest replies are store for commiting data
    pub closest_replies: Vec<Arc<InResponse>>,
}

impl Query {
    // TODO use a builder struct instead
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: QueryId,
        cmd: Command,
        parallelism: NonZeroUsize,
        local_id: IdBytes,
        target: IdBytes,
        value: Option<Vec<u8>>,
        peers: Vec<PeerId>,
        bootstrap: Vec<Peer>,
        commit: Commit,
    ) -> Self {
        Self {
            id,
            parallelism,
            peer_iter: ClosestPeersIter::new(target, bootstrap),
            cmd,
            stats: QueryStats::empty(),
            value,
            inner: QueryTable::new(local_id, target, peers),
            commit,
            closest_replies: vec![],
        }
    }

    // TODO use binary search ot insert
    // TODO in theory, new elements distances get smaller. So maybe reverse the list.
    #[instrument(skip_all)]
    fn maybe_update_closest_replies(&mut self, data: Arc<InResponse>) -> Option<usize> {
        let reply_distance = self.peer_iter.target.distance(data.response.id?);
        let replace = self.closest_replies.len() >= K_VALUE.into();

        if self.closest_replies.is_empty() {
            self.closest_replies.insert(0, data.clone());
            return Some(0);
        }
        for (i, cur) in self.closest_replies.iter().enumerate() {
            if reply_distance
                < self
                    .peer_iter
                    .target
                    .distance(cur.response.id.expect("TODO this should be a PeerId"))
            {
                if replace {
                    self.closest_replies[i] = data.clone();
                } else {
                    self.closest_replies.insert(i, data.clone());
                }
                trace!(
                    closest_replies.len = self.closest_replies.len(),
                    "Inerted response at [{i}]"
                );
                return Some(i);
            }
        }
        trace!("Response farther than all current replies");
        None
    }
    pub fn command(&self) -> Command {
        self.cmd
    }

    pub fn target(&self) -> &IdBytes {
        self.inner.target()
    }
    pub fn value(&self) -> Option<&Vec<u8>> {
        self.value.as_ref()
    }

    pub fn id(&self) -> QueryId {
        self.id
    }

    // TODO unused
    pub(crate) fn _on_timeout(&mut self, peer: Peer) {
        self.stats.failure += 1;
        for (p, state) in self.inner.peers_mut() {
            if p.addr == peer.addr {
                *state = PeerState::Failed;
                break;
            }
        }
        self.peer_iter.on_failure(&peer);
    }

    /// Received a response to a requested driven by this query.
    #[instrument(skip(self, data))]
    pub(crate) fn inject_response(&mut self, data: Arc<InResponse>) -> Option<Arc<InResponse>> {
        use crate::Progress as P;
        use Commit as C;

        match &mut self.commit {
            // Commit is in progress
            C::Auto(prog @ (P::AwaitingReplies(_) | P::Sending(_)))
            | C::Custom(prog @ (P::AwaitingReplies(_) | P::Sending(_))) => {
                warn!("recieved a response! for tid {}", data.response.tid);
                prog.recieved_tid(data.response.tid);
            }
            // Before commit
            _ => {
                self.maybe_update_closest_replies(data.clone());
                let remote = data
                    .response
                    .id
                    .map(|id| PeerId::new(data.peer.addr, IdBytes::from(id)));

                if data.response.is_error() {
                    warn!(error = data.response.error, "Error in peer response");
                    self.stats.failure += 1;
                    self.peer_iter.on_failure(&data.peer);
                    if let Some(ref remote) = remote {
                        if let Some(state) = self.inner.peers_mut().get_mut(remote) {
                            *state = PeerState::Failed;
                        }
                    }
                    return None;
                }

                self.stats.success += 1;
                self.peer_iter
                    .on_success(&data.peer, &data.response.closer_nodes);

                if let Some(token) = &data.response.token {
                    if let Some(remote) = remote {
                        self.inner.add_verified(
                            remote,
                            token.to_vec(),
                            Some(data.response.to.addr),
                        );
                    }
                }
            }
        }

        Some(data)
    }

    fn send(&mut self, peer: Peer) -> QueryEvent {
        QueryEvent::Query {
            command: self.cmd,
            target: *self.target(),
            value: self.value.clone(),
            peer,
        }
    }

    #[instrument(skip_all)]
    fn poll(&mut self, now: Instant) -> Poll<Option<QueryEvent>> {
        let pis = self.peer_iter.next(now);
        info!("next peer iter state: {pis:?}");
        match pis {
            PeersIterState::Waiting(peer) => {
                return if let Some(peer) = peer {
                    Poll::Ready(Some(self.send(peer)))
                } else {
                    Poll::Pending
                };
            }
            PeersIterState::WaitingAtCapacity => return Poll::Pending,
            PeersIterState::Finished => {}
        };

        let out = match poll_commit(&mut self.commit, self.id) {
            Poll::Ready(op) => Poll::Ready(op.map(QueryEvent::Commit)),
            Poll::Pending => Poll::Pending,
        };

        trace!("Query::poll result {out:?}");
        out
    }

    /// Consumes the query, producing the final `QueryResult`.
    pub fn into_result(&self) -> QueryResult {
        QueryResult {
            peers: self.inner.peers_iter(),
            query_id: self.id,
            stats: self.stats.clone(),
            cmd: self.cmd,
            closest_replies: self.closest_replies.clone(),
        }
    }
}

/// NB this is not idempotent
#[instrument(skip_all)]
fn poll_commit(commit: &mut Commit, query_id: QueryId) -> Poll<Option<CommitEvent>> {
    use crate::Progress as P;
    use Commit as C;
    trace!("polling commit: {commit:?}");
    match commit {
        C::No | C::Auto(P::Done) | C::Custom(P::Done) => Poll::Ready(None),
        C::Auto(P::BeforeStart) => {
            let (tx, rx) = mpsc::channel(DEFAULT_COMMIT_CHANNEL_SIZE);
            *commit = C::Auto(P::Sending((rx, Default::default())));
            // RpcDht should recieve this and send the query messages
            Poll::Ready(Some(CommitEvent::AutoStart((tx, query_id))))
        }
        C::Custom(P::BeforeStart) => {
            let (tx, rx) = mpsc::channel(DEFAULT_COMMIT_CHANNEL_SIZE);
            *commit = C::Custom(P::Sending((rx, Default::default())));
            Poll::Ready(Some(CommitEvent::CustomStart((tx, query_id))))
        }
        C::Auto(P::Sending(_)) => Poll::Pending,
        C::Custom(P::Sending((rx, _tids))) => {
            let mut out = vec![];
            while let Some(e) = rx.try_next().ok().flatten() {
                out.push(e)
            }
            if !out.is_empty() {
                let sending_done = CommitEvent::SendRequests((out, query_id));
                return Poll::Ready(Some(sending_done));
            }
            Poll::Pending
        }
        C::Custom(P::AwaitingReplies(ids_waiting_on)) => {
            debug!("Custom still waiting on [{}] replies", ids_waiting_on.len());
            Poll::Pending
        }
        C::Auto(P::AwaitingReplies(ids_waiting_on)) => {
            debug!("Auto still waiting on [{}] replies", ids_waiting_on.len());
            Poll::Pending
        }
    }
}

#[derive(Debug)]
pub enum QueryEvent {
    Commit(CommitEvent),
    Query {
        peer: Peer,
        command: Command,
        target: IdBytes,
        value: Option<Vec<u8>>,
    },
    RemoveNode {
        id: IdBytes,
    },
    MissingRoundtripToken {
        peer: Peer,
    },
}

/// Represents an incoming query with a custom command.
#[derive(Debug, Clone)]
pub struct CommandQuery {
    /// The Id of the query
    pub tid: u16,
    /// Command def
    pub command: usize,
    /// the node who sent the query
    pub peer: Peer,
    /// the query target (32 byte target)
    pub target: IdBytes,
    /// the query payload decoded with the inputEncoding
    pub value: Option<Vec<u8>>,
}

impl CommandQuery {
    pub fn into_response_with_error(self, err: impl Into<usize>) -> CommandQueryResponse {
        let mut resp = CommandQueryResponse::from(self);
        resp.msg.error = err.into();
        resp
    }
}

/// Outgoing response to a `CommandQuery`
#[derive(Debug, Clone)]
pub struct CommandQueryResponse {
    pub msg: ReplyMsgData,
    pub peer: Peer,
    pub target: IdBytes,
}

impl From<CommandQuery> for CommandQueryResponse {
    fn from(q: CommandQuery) -> Self {
        let msg = ReplyMsgData {
            tid: q.tid,
            to: q.peer.clone(),
            id: None,
            token: None,
            closer_nodes: vec![],
            value: q.value,
            error: 0,
        };

        Self {
            msg,
            peer: q.peer,
            target: q.target,
        }
    }
}
/// The result of a `Query`.
#[derive(Debug)]
pub struct QueryResult {
    /// The ID of the query that finished.
    pub query_id: QueryId,
    /// The Command of the query.
    pub cmd: Command,
    /// The collected query statistics.
    pub stats: QueryStats,
    /// The successfully contacted peers.
    pub peers: Vec<(PeerId, PeerState)>,
    /// Closest replies to the target
    pub closest_replies: Vec<Arc<InResponse>>,
}

/// Execution statistics of a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryStats {
    requests: u32,
    success: u32,
    failure: u32,
    start: Option<Instant>,
    end: Option<Instant>,
}

impl QueryStats {
    pub fn empty() -> Self {
        QueryStats {
            requests: 0,
            success: 0,
            failure: 0,
            start: None,
            end: None,
        }
    }

    /// Gets the total number of requests initiated by the query.
    pub fn num_requests(&self) -> u32 {
        self.requests
    }

    /// Gets the number of successful requests.
    pub fn num_successes(&self) -> u32 {
        self.success
    }

    /// Gets the number of failed requests.
    pub fn num_failures(&self) -> u32 {
        self.failure
    }

    /// Gets the number of pending requests.
    ///
    /// > **Note**: A query can finish while still having pending
    /// > requests, if the termination conditions are already met.
    pub fn num_pending(&self) -> u32 {
        self.requests - (self.success + self.failure)
    }

    /// Gets the duration of the query.
    ///
    /// If the query has not yet finished, the duration is measured from the
    /// start of the query to the current instant.
    ///
    /// If the query did not yet start (i.e. yield the first peer to contact),
    /// `None` is returned.
    pub fn duration(&self) -> Option<Duration> {
        if let Some(s) = self.start {
            if let Some(e) = self.end {
                Some(e - s)
            } else {
                Some(Instant::now() - s)
            }
        } else {
            None
        }
    }

    /// Merges these stats with the given stats of another query,
    /// e.g. to accumulate statistics from a multi-phase query.
    ///
    /// Counters are merged cumulatively while the instants for
    /// start and end of the queries are taken as the minimum and
    /// maximum, respectively.
    pub fn merge(self, other: QueryStats) -> Self {
        QueryStats {
            requests: self.requests + other.requests,
            success: self.success + other.success,
            failure: self.failure + other.failure,
            start: match (self.start, other.start) {
                (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
                (a, b) => a.or(b),
            },
            end: std::cmp::max(self.end, other.end),
        }
    }
}
/// Unique identifier for an active query.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QueryId(pub usize);

impl Display for QueryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QueryId({})", self.0)
    }
}
