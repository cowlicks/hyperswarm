//! Hyperswarm - Peer-to-peer networking with topic-based discovery

#![warn(
    redundant_lifetimes,
    non_local_definitions,
    clippy::needless_pass_by_ref_mut,
    clippy::enum_glob_use
)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use dht_rpc::{IdBytes, Peer};
use futures::{Future, Stream, stream::FuturesUnordered};
use hyperdht::{
    Server,
    adht::{Dht, LookupResponse, PeerHandshakeArgs},
};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

mod config;
mod connection_set;
mod error;
mod peer_discovery;
mod peer_info;
mod queue;
mod retry;

pub use config::SwarmConfig;
pub use connection_set::{AddResult, ConnectionInfo, ConnectionSet};
pub use error::{Error, Result};
pub use peer_discovery::PeerDiscovery;
pub use peer_info::{ConnectionState, PeerInfo, PeerOrigin, Priority, TrustLevel};
pub use queue::{PeerQueue, QueuedPeer};
pub use retry::{RetryEntry, RetryTimer};

// Re-export from dependencies
pub use dht_rpc::{DhtConfig, IdBytes as Topic};
pub use hyperdht::{Connection, Keypair, PublicKey, adht::ConnectFuture};
use utils::PeriodicJob;

const DEFAULT_AUTO_CONNECT_JOB_INTERVAL: Duration = Duration::from_millis(100);
// TODO when we need more options, turn JoinOpts into a struct and make this enum a field.
#[derive(Debug, Default)]
pub enum JoinOpts {
    Client,
    Server,
    #[default]
    Both,
}

impl JoinOpts {
    pub fn server(&self) -> bool {
        matches!(self, JoinOpts::Server) || matches!(self, JoinOpts::Both)
    }
    pub fn client(&self) -> bool {
        matches!(self, JoinOpts::Client) || matches!(self, JoinOpts::Both)
    }
    pub fn both(&self) -> bool {
        matches!(self, JoinOpts::Both)
    }
}

/// Event emitted when a connection is established
#[derive(Debug)]
pub struct ConnectionEvent {
    /// The established connection
    pub connection: Connection,
    /// Remote peer's public key
    pub remote_public_key: IdBytes,
    // TODO consider turning (client, topics) into an emun like
    // `ConnectionKind { Client { topics: []}, Server };
    /// Whether we initiated (client) or accepted (server)
    pub client: bool,
    /// Topics this peer was discovered on (empty for server connections)
    pub topics: Vec<IdBytes>,
}

/// The main Hyperswarm instance
pub struct Swarm {
    inner: Arc<RwLock<SwarmInner>>,
    /// Receiver for connection events (client connections)
    connection_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ConnectionEvent>>>,
}

struct SwarmInner {
    dht: Dht,
    keypair: Keypair,
    config: SwarmConfig,
    connections: ConnectionSet,
    peers: HashMap<IdBytes, PeerInfo>,
    discoveries: HashMap<IdBytes, PeerDiscovery>,
    /// Priority queue for connection scheduling
    queue: PeerQueue,
    /// Retry timer for failed connections
    retry_timer: RetryTimer,
    /// Channel sender for connection events
    connection_tx: mpsc::Sender<ConnectionEvent>,
    /// Pending connection futures
    pending_connections: FuturesUnordered<PendingConnection>,
    waker: Option<Waker>,
    auto_connect_job: PeriodicJob,
    /// The hyperdht server, created lazily on first join with server mode
    server: Option<Server>,
}

pub enum SwarmEvent {
    AnnounceComplete(Result<IdBytes>),
    LookupComplete(Result<IdBytes>),
}

impl Stream for SwarmInner {
    type Item = Result<SwarmEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        _ = Pin::new(&mut self.dht).poll_next(cx);

        if self.waker.is_none() {
            self.waker = Some(cx.waker().clone());
        }

        self.poll_server(cx);

        if let Poll::Ready(()) = self.auto_connect_job.poll_now(cx) {
            self.auto_connect_job();
        }

        self.poll_discoveries(cx);

        while let Poll::Ready(Some((pk, result))) =
            Pin::new(&mut self.pending_connections).poll_next(cx)
        {
            self.handle_connection_result(pk, result);
        }

        Poll::Pending
    }
}

impl SwarmInner {
    fn name(&self) -> String {
        self.dht.name()
    }
    fn poll_server(&mut self, cx: &mut Context<'_>) {
        let Some(server) = &mut self.server else {
            return;
        };
        while let Poll::Ready(Some(result)) = Pin::new(&mut *server).poll_next(cx) {
            match result {
                Ok(connection) => {
                    let remote_public_key = connection
                        .get_remote_static()
                        .map(IdBytes)
                        .unwrap_or_else(|| panic!("Server connection without remote public key"));
                    debug!(?remote_public_key, "server connection accepted");
                    self.connections.add(remote_public_key, false);
                    let _ = self.connection_tx.try_send(ConnectionEvent {
                        connection,
                        client: false,
                        remote_public_key,
                        topics: vec![],
                    });
                }
                Err(e) => {
                    error!(?e, "server connection error");
                }
            }
        }
    }
    fn maybe_wake(&self) {
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }
    // TODO Doing a clone of these for every poll is bad. Fix when we implement
    // PeerDiscovery sessions.
    //
    // We should have Server emit an  event when relay addresses are updated, then we can handle it
    // and set them in each peer-discovery.
    // Or better yet have a way peer-discovery's announce to get them directly from the Server.
    // Currently we're just proxying them from Server -> Swarm -> PeerDiscovery.
    fn get_relay_addresses(&self) -> Vec<SocketAddr> {
        self.server
            .as_ref()
            .map(|s| s.relay_addresses())
            .unwrap_or_default()
    }
    fn poll_discoveries(&mut self, cx: &mut Context<'_>) {
        let relay_addresses = self.get_relay_addresses();
        let mut events = Vec::new();
        for (topic, discovery) in self.discoveries.iter_mut() {
            discovery.maybe_set_relay_addresses(&relay_addresses);
            while let Poll::Ready(Some(result)) = Pin::new(&mut *discovery).poll_next(cx) {
                events.push((*topic, result));
            }
        }
        for (topic, result) in events {
            match result {
                Ok(Some(response)) => self.handle_lookup_response(topic, response),
                Ok(None) => {}
                Err(e) => error!(?topic, ?e, "discovery error"),
            }
        }
    }
    fn handle_lookup_response(&mut self, topic: IdBytes, response: LookupResponse) {
        // Check if we're still interested in this topic
        // TODO we should abort the lookup here since we aren't interested
        if !self.discoveries.contains_key(&topic) {
            return;
        }

        for peer in response.peers {
            let pk = IdBytes(*peer.public_key);
            // Convert relay addresses to SocketAddr
            let relay_addrs: Vec<std::net::SocketAddr> =
                peer.relay_addresses.iter().map(|a| (*a).into()).collect();
            debug!(?pk, ?relay_addrs, "discovered peer");

            let peer_already_connected = self.connections.has(&pk);
            let peer_is_new = !self.peers.contains_key(&pk);

            let peer_info = self
                .peers
                .entry(pk)
                .or_insert_with(|| PeerInfo::new(pk))
                .add_topic(topic)
                .add_relay_addresses(relay_addrs);

            // Enqueue for connection if:
            if self.config.auto_connect     // Auto-connect enabled
                && !peer_already_connected  // Not already connected
                && peer_info.state.is_idle() // Not busy (queued/waiting/connecting)
                // Nor banned
                && !peer_info.trust.is_banned()
            {
                peer_info.state = ConnectionState::Queued;
                let priority = peer_info.priority;
                self.queue.push(QueuedPeer {
                    public_key: pk,
                    priority,
                    queued_at: Instant::now(),
                    shuffle_key: rand::random(),
                });
                if peer_is_new {
                    debug!(?pk, "enqueued new peer for connection");
                }
            }
        }
    }

    fn handle_connection_result(&mut self, pk: IdBytes, result: hyperdht::Result<Connection>) {
        match result {
            Ok(connection) => {
                debug!(?pk, "connection succeeded");

                let topics: Vec<IdBytes> = self
                    .peers
                    .get_mut(&pk)
                    .map(|peer_info| {
                        peer_info.connected();
                        peer_info.topics.iter().copied().collect()
                    })
                    .unwrap_or_default();

                let add_result = self.connections.add(pk, true);
                if add_result != AddResult::KeptExisting {
                    let _ = self.connection_tx.try_send(ConnectionEvent {
                        connection,
                        client: true,
                        remote_public_key: pk,
                        topics,
                    });
                }
            }
            Err(e) => {
                debug!(?pk, ?e, "connection failed");

                let Some(peer_info) = self.peers.get_mut(&pk) else {
                    return;
                };
                peer_info.disconnected(); // Increments attempts, updates priority

                // Schedule retry if enabled and not banned
                let should_retry = self.config.auto_retry
                    && peer_info.reconnecting
                    && !peer_info.trust.is_banned()
                    && peer_info.priority != Priority::VeryLow;

                if should_retry {
                    peer_info.state = ConnectionState::Waiting;
                    let attempts = peer_info.attempts;
                    self.retry_timer.schedule(RetryEntry::new(pk, attempts));
                }
            }
        }
    }

    fn auto_connect_job(&mut self) {
        for entry in self.retry_timer.get_ready() {
            let already_connected = self.connections.has(&entry.public_key);

            let Some(peer_info) = self.peers.get_mut(&entry.public_key) else {
                continue;
            };
            if !peer_info.trust.is_banned() && peer_info.state.is_waiting() && !already_connected {
                peer_info.state = ConnectionState::Queued;
                self.queue.push(QueuedPeer {
                    public_key: entry.public_key,
                    priority: peer_info.priority,
                    queued_at: Instant::now(),
                    shuffle_key: rand::random(),
                });
            }
        }
        self.attempt_connections();
    }
    fn attempt_connections(&mut self) {
        loop {
            // Get next peer to connect (if within limits)
            let (pk, relay_addresses) = {
                // Check limits
                if self.pending_connections.len() >= self.config.max_parallel {
                    break;
                }
                if self.connections.len() >= self.config.max_peers {
                    break;
                }

                // Get next peer from queue
                let Some(queued) = self.queue.pop() else {
                    break; // no more peers
                };

                // Check if already connected before getting mutable peer borrow
                let already_connected = self.connections.has(&queued.public_key);

                // Update peer state
                let peer_info = match self.peers.get_mut(&queued.public_key) {
                    Some(p) => p,
                    None => continue, // Peer was removed
                };

                // Skip if already connected or not queued
                if already_connected || !peer_info.state.is_queued() {
                    peer_info.state = ConnectionState::Idle;
                    continue;
                }

                // Get relay addresses before marking as connecting
                let relay_addresses = peer_info.relay_addresses.clone();

                peer_info.state = ConnectionState::Connecting;

                (queued.public_key, relay_addresses)
            };

            let pub_key = PublicKey::from(pk.0);
            let closest_nodes = (!relay_addresses.is_empty())
                .then(|| relay_addresses.iter().map(Peer::from).collect());
            {
                let future = self.dht.connect(pub_key, closest_nodes);
                self.pending_connections
                    .push(PendingConnection { pk, future });
                self.maybe_wake();
            };
        }
    }
    fn join(&mut self, topic: IdBytes, opts: JoinOpts) {
        if opts.server() && self.server.is_none() {
            self.server = Some(self.dht.listen(self.keypair.clone()));
        }
        let discovery = PeerDiscovery::new(
            topic,
            opts,
            self.dht.clone(),
            self.keypair.clone(),
            self.get_relay_addresses(),
        );
        self.discoveries.insert(topic, discovery);
        self.maybe_wake();
    }
}

impl Swarm {
    pub fn name(&self) -> String {
        self.inner.read().unwrap().name()
    }
    /// Create a new Swarm with the given config
    pub async fn with_config(config: SwarmConfig) -> Result<Self> {
        let keypair = Keypair::default();
        let dht = Dht::with_config(config.dht_config).await?;
        let (connection_tx, connection_rx) = mpsc::channel(64);

        let inner = Arc::new(RwLock::new(SwarmInner {
            dht,
            keypair,
            config: SwarmConfig {
                max_parallel: config.max_parallel,
                max_peers: config.max_peers,
                auto_connect: config.auto_connect,
                auto_retry: config.auto_retry,
                dht_config: DhtConfig::default(), // Not used after init
            },
            connections: ConnectionSet::new(),
            peers: HashMap::new(),
            discoveries: HashMap::new(),
            queue: PeerQueue::new(),
            retry_timer: RetryTimer::new(),
            connection_tx,
            pending_connections: Default::default(),
            waker: Default::default(),
            auto_connect_job: PeriodicJob::new(DEFAULT_AUTO_CONNECT_JOB_INTERVAL),
            server: None,
        }));

        let swarm = Self {
            inner: inner.clone(),
            connection_rx: Arc::new(tokio::sync::Mutex::new(connection_rx)),
        };

        Ok(swarm)
    }

    /// Create a new Swarm with the given DHT config (convenience method)
    pub async fn new(dht_config: DhtConfig) -> Result<Self> {
        Self::with_config(SwarmConfig::new(dht_config)).await
    }

    /// Create with default config
    pub async fn default_config() -> Result<Self> {
        Self::with_config(SwarmConfig::default()).await
    }

    /// Get the swarm's public key
    pub fn public_key(&self) -> IdBytes {
        let inner = self.inner.read().unwrap();
        IdBytes(*inner.keypair.public)
    }

    /// Get a clone of the keypair
    pub fn keypair(&self) -> Keypair {
        self.inner.read().unwrap().keypair.clone()
    }

    /// Number of connections
    pub fn connections_count(&self) -> usize {
        self.inner.read().unwrap().connections.len()
    }

    /// Number of known peers
    pub fn peers_count(&self) -> usize {
        self.inner.read().unwrap().peers.len()
    }

    pub fn flush(&self) -> FlushAnnouncesAndLookups {
        FlushAnnouncesAndLookups {
            inner: self.inner.clone(),
        }
    }

    /// Join a topic for peer discovery
    pub fn join(&self, topic: IdBytes, opts: JoinOpts) {
        self.inner.write().unwrap().join(topic, opts);
    }

    /// Leave a topic
    pub fn leave(&self, topic: &IdBytes) {
        let mut inner = self.inner.write().unwrap();
        inner.discoveries.remove(topic);
        // TODO: Unannounce if was server
    }

    /// Check if joined to a topic
    pub fn has_topic(&self, topic: &IdBytes) -> bool {
        self.inner.read().unwrap().discoveries.contains_key(topic)
    }

    /// Get number of active topic discoveries
    pub fn topics_count(&self) -> usize {
        self.inner.read().unwrap().discoveries.len()
    }

    /// Connect to a peer by their public key
    pub fn connect(&self, pub_key: PublicKey) -> impl Future<Output = Result<Connection>> {
        let fut = self.inner.read().unwrap().dht.connect(pub_key, None);
        async move { Ok(fut.await?) }
    }

    /// Bootstrap the DHT connection
    pub fn bootstrap(&self) -> dht_rpc::BootstrapFuture {
        self.inner.read().unwrap().dht.bootstrap()
    }

    /// Get the local socket address
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.inner.read().unwrap().dht.local_addr()?)
    }

    /// Connect to a peer at a specific address (lower level API)
    pub fn peer_handshake(
        &self,
        remote_public_key: PublicKey,
        destination: std::net::SocketAddr,
    ) -> impl Future<Output = Result<Connection>> {
        let phs = {
            self.inner
                .read()
                .unwrap()
                .dht
                .peer_handshake(PeerHandshakeArgs::new(remote_public_key, destination))
        };
        async move { phs.await.map_err(Into::into) }
    }

    /// Get a stream of connection events (both client & server).
    pub fn connections(&self) -> ConnectionStream {
        ConnectionStream {
            inner: self.inner.clone(),
            rx: self.connection_rx.clone(),
        }
    }
}

impl Stream for Swarm {
    type Item = Result<SwarmEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut guard = self.inner.write().unwrap();
        Pin::new(&mut *guard).poll_next(cx)
    }
}

/// Stream that yields connection events (both client and server)
pub struct ConnectionStream {
    inner: Arc<RwLock<SwarmInner>>,
    /// Receiver for connection events (both client and server)
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ConnectionEvent>>>,
}

impl Stream for ConnectionStream {
    type Item = Result<ConnectionEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        {
            let mut inner = self.inner.write().unwrap();
            _ = Pin::new(&mut *inner).poll_next(cx);
        }

        if let Ok(mut rx) = self.rx.try_lock() {
            match rx.poll_recv(cx) {
                Poll::Ready(Some(event)) => {
                    debug!("[swarm] ConnectionStream yielding connection event");
                    return Poll::Ready(Some(Ok(event)));
                }
                Poll::Ready(None) => {
                    debug!("[swarm] ConnectionStream ended (sender dropped)");
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    debug!(
                        "[swarm] ConnectionStream pending (no connection yet), queue_len={}, pending_conns={}",
                        self.inner.read().unwrap().queue.len(),
                        self.inner.read().unwrap().pending_connections.len()
                    );
                }
            }
        } else {
            debug!("[swarm] ConnectionStream try_lock failed");
        }

        Poll::Pending
    }
}

impl Clone for Swarm {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            connection_rx: self.connection_rx.clone(),
        }
    }
}

pub struct FlushAnnouncesAndLookups {
    inner: Arc<RwLock<SwarmInner>>,
}

impl Future for FlushAnnouncesAndLookups {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.inner.write().unwrap();
        let _ = Stream::poll_next(Pin::new(&mut *inner), cx);
        if inner
            .discoveries
            .values()
            .all(|d| d.is_first_round_complete())
        {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

struct PendingConnection {
    pk: IdBytes,
    future: ConnectFuture,
}

impl Future for PendingConnection {
    type Output = (IdBytes, hyperdht::Result<Connection>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.future).poll(cx) {
            Poll::Ready(result) => Poll::Ready((self.pk, result)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_swarm() {
        let swarm = Swarm::default_config().await.unwrap();
        assert_eq!(swarm.connections_count(), 0);
    }

    #[tokio::test]
    async fn test_join_leave() {
        let swarm = Swarm::default_config().await.unwrap();
        let topic = IdBytes::random();

        assert!(!swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 0);

        swarm.join(topic, JoinOpts::Both);
        assert!(swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 1);

        swarm.leave(&topic);
        assert!(!swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 0);
    }
}
