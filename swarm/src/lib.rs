//! Hyperswarm - Peer-to-peer networking with topic-based discovery

#![warn(
    redundant_lifetimes,
    non_local_definitions,
    clippy::needless_pass_by_ref_mut,
    clippy::enum_glob_use
)]

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use dht_rpc::{Commit, IdBytes, Peer};
use futures::{
    Future, Stream,
    stream::{FuturesUnordered, SelectAll},
};
use hyperdht::adht::{Announce, Dht, Lookup, LookupResponse, PeerHandshakeArgs};
use tokio::sync::mpsc;
use tracing::{debug, error, trace};

mod config;
mod connection_set;
mod error;
mod peer_info;
mod queue;
mod retry;

pub use config::SwarmConfig;
pub use connection_set::{AddResult, ConnectionInfo, ConnectionSet};
pub use error::{Error, Result};
pub use peer_info::{PeerInfo, Priority};
pub use queue::{PeerQueue, QueuedPeer};
pub use retry::{RetryEntry, RetryTimer};

// Re-export from dependencies
pub use dht_rpc::{DhtConfig, IdBytes as Topic};
pub use hyperdht::{Connection, Keypair, PublicKey, adht::ConnectFuture};

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

/// Tracks discovery state for a topic
#[derive(Debug)]
struct Discovery {
    #[allow(dead_code)]
    topic: IdBytes,
    #[allow(dead_code)]
    server: bool,
    #[allow(dead_code)]
    client: bool,
}

/// Event emitted when a connection is established
#[derive(Debug)]
pub struct ConnectionEvent {
    /// The established connection
    pub connection: Connection,
    /// Whether we initiated (client) or accepted (server)
    pub client: bool,
    /// Remote peer's public key
    pub remote_public_key: IdBytes,
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
    destroyed: bool,
    listening: bool,
    connections: ConnectionSet,
    peers: HashMap<IdBytes, PeerInfo>,
    discoveries: HashMap<IdBytes, Discovery>,
    /// Priority queue for connection scheduling
    queue: PeerQueue,
    /// Retry timer for failed connections
    retry_timer: RetryTimer,
    /// Number of in-flight connection attempts
    pending_connects: usize,
    /// Channel sender for connection events
    connection_tx: mpsc::Sender<ConnectionEvent>,
    /// Pending announce futures
    pending_announces: FuturesUnordered<PendingAnnounce>,
    /// Pending lookup streams
    pending_lookups: SelectAll<PendingLookup>,
}

impl SwarmInner {
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
                .or_insert_with(|| PeerInfo::new(pk).with_topic(topic));
            peer_info.add_relay_addresses(relay_addrs);

            // Enqueue for connection if:
            if self.config.auto_connect     // Auto-connect enabled
                && !peer_already_connected  // Not already connected
                && !peer_info.queued        // Nor already queued
                && !peer_info.connecting    // Nor connecting
                // Nor banned
                && !peer_info.banned
            {
                peer_info.queued = true;
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
}

enum SwarmEvent {
    #[expect(unused)]
    AnnounceComplete(Result<IdBytes>),
    #[expect(unused)]
    LookupComplete(Result<IdBytes>),
}

impl Stream for SwarmInner {
    type Item = Result<SwarmEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(Some(res)) = Pin::new(&mut self.pending_announces).poll_next(cx) {
            return Poll::Ready(Some(Ok(SwarmEvent::AnnounceComplete(res))));
        }

        while let Poll::Ready(Some((topic, result))) =
            Pin::new(&mut self.pending_lookups).poll_next(cx)
        {
            match result {
                Ok(Some(response)) => self.handle_lookup_response(topic, response),
                Ok(None) => {
                    trace!(?topic, "lookup complete");
                }
                Err(e) => {
                    error!(?topic, ?e, "lookup error");
                }
            }
        }

        Poll::Pending
    }
}

impl SwarmInner {
    fn name(&self) -> String {
        self.dht.name()
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
            destroyed: false,
            listening: false,
            connections: ConnectionSet::new(),
            peers: HashMap::new(),
            discoveries: HashMap::new(),
            queue: PeerQueue::new(),
            retry_timer: RetryTimer::new(),
            pending_connects: 0,
            connection_tx,
            pending_announces: Default::default(),
            pending_lookups: Default::default(),
        }));

        let swarm = Self {
            inner: inner.clone(),
            connection_rx: Arc::new(tokio::sync::Mutex::new(connection_rx)),
        };

        // Spawn auto-connect task if enabled
        if config.auto_connect {
            swarm.spawn_auto_connect_task();
        }

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

    /// Check if destroyed
    pub fn destroyed(&self) -> bool {
        self.inner.read().unwrap().destroyed
    }

    /// Check if listening for connections
    pub fn listening(&self) -> bool {
        self.inner.read().unwrap().listening
    }

    /// Start listening for incoming connections
    /// Returns a Server stream that yields connections
    pub fn listen(&self) -> Result<ServerFuture> {
        let mut inner = self.inner.write().unwrap();
        if inner.destroyed {
            return Err(Error::Destroyed);
        }
        inner.listening = true;
        let server = inner.dht.listen(inner.keypair.clone());
        Ok(ServerFuture::new(Some(self.inner.clone()), server))
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
    pub fn join(&self, topic: IdBytes, opts: JoinOpts) -> Result<()> {
        let (lookup, announce) = {
            let mut inner = self.inner.write().unwrap();
            if inner.destroyed {
                return Err(Error::Destroyed);
            }

            let discovery = Discovery {
                topic,
                server: opts.server(),
                client: opts.client(),
            };
            inner.discoveries.insert(topic, discovery);

            let lookup = if opts.client() {
                Some(inner.dht.lookup(topic, Commit::No)?)
            } else {
                None
            };

            let announce = if opts.server() {
                Some(inner.dht.announce(topic, inner.keypair.clone(), vec![]))
            } else {
                None
            };

            (lookup, announce)
        };

        if let Some(lookup) = lookup {
            let pl = PendingLookup { topic, lookup };
            self.inner.write().unwrap().pending_lookups.push(pl);
        }

        if let Some(announce) = announce {
            self.inner
                .write()
                .unwrap()
                .pending_announces
                .push(PendingAnnounce::new(topic, announce));
        }

        Ok(())
    }

    /// Leave a topic
    pub fn leave(&self, topic: &IdBytes) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        if inner.destroyed {
            return Err(Error::Destroyed);
        }

        inner.discoveries.remove(topic);
        // TODO: Unannounce if was server
        Ok(())
    }

    /// Check if joined to a topic
    pub fn has_topic(&self, topic: &IdBytes) -> bool {
        self.inner.read().unwrap().discoveries.contains_key(topic)
    }

    /// Get number of active topic discoveries
    pub fn topics_count(&self) -> usize {
        self.inner.read().unwrap().discoveries.len()
    }

    /// Destroy the swarm
    pub fn destroy(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.destroyed = true;
        inner.discoveries.clear();
    }

    /// Connect to a peer by their public key
    pub fn connect(&self, pub_key: PublicKey) -> impl Future<Output = Result<Connection>> {
        let destroyed = self.inner.read().unwrap().destroyed;
        let fut = self.inner.read().unwrap().dht.connect(pub_key, None);
        async move {
            if destroyed {
                return Err(Error::Destroyed);
            }
            Ok(fut.await?)
        }
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
        let (destroyed, phs) = {
            let inner = self.inner.read().unwrap();
            (
                inner.destroyed,
                inner
                    .dht
                    .peer_handshake(PeerHandshakeArgs::new(remote_public_key, destination)),
            )
        };
        async move {
            if destroyed {
                return Err(Error::Destroyed);
            }
            phs.await.map_err(Into::into)
        }
    }

    /// Get a stream of connection events (both client and server)
    pub fn connections(&self) -> ConnectionStream {
        ConnectionStream {
            inner: self.inner.clone(),
            connection_rx: self.connection_rx.clone(),
            server: None,
        }
    }

    /// Start listening and get unified connection stream
    pub async fn listen_all(&self) -> Result<ConnectionStream> {
        let server = self.listen()?;
        Ok(ConnectionStream {
            inner: self.inner.clone(),
            connection_rx: self.connection_rx.clone(),
            server: Some(server.await?),
        })
    }

    /// Spawn the auto-connect background task
    fn spawn_auto_connect_task(&self) {
        let inner = self.inner.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));

            loop {
                interval.tick().await;

                // Check if destroyed
                {
                    let guard = inner.read().unwrap();
                    if guard.destroyed {
                        break;
                    }
                }

                // Process retry timer - re-enqueue ready peers
                {
                    let mut guard = inner.write().unwrap();
                    let ready_entries = guard.retry_timer.get_ready();
                    for entry in ready_entries {
                        // Check connections first before getting mutable peer borrow
                        let already_connected = guard.connections.has(&entry.public_key);

                        if let Some(peer_info) = guard.peers.get_mut(&entry.public_key) {
                            peer_info.waiting = false;
                            if !peer_info.banned && !peer_info.connecting && !already_connected {
                                peer_info.queued = true;
                                let priority = peer_info.priority;
                                guard.queue.push(QueuedPeer {
                                    public_key: entry.public_key,
                                    priority,
                                    queued_at: Instant::now(),
                                    shuffle_key: rand::random(),
                                });
                            }
                        }
                    }
                }

                // Attempt connections from queue
                Self::attempt_connections(&inner).await;
            }
        });
    }

    /// Attempt to connect to peers from the queue
    async fn attempt_connections(inner: &Arc<RwLock<SwarmInner>>) {
        loop {
            // Get next peer to connect (if within limits)
            let (pk, pub_key_bytes, relay_addresses, connection_tx) = {
                let mut guard = inner.write().unwrap();

                // Check limits
                if guard.pending_connects >= guard.config.max_parallel {
                    break;
                }
                if guard.connections.len() >= guard.config.max_peers {
                    break;
                }

                // Get next peer from queue
                let Some(queued) = guard.queue.pop() else {
                    break; // no more peers
                };

                // Check if already connected before getting mutable peer borrow
                let already_connected = guard.connections.has(&queued.public_key);

                // Update peer state
                let peer_info = match guard.peers.get_mut(&queued.public_key) {
                    Some(p) => p,
                    None => continue, // Peer was removed
                };

                // Skip if already connected or connecting
                if already_connected || peer_info.connecting {
                    peer_info.queued = false;
                    continue;
                }

                // Get relay addresses before marking as connecting
                let relay_addresses = peer_info.relay_addresses.clone();

                peer_info.queued = false;
                peer_info.connecting = true;
                peer_info.last_attempt = Some(Instant::now());
                guard.pending_connects += 1;

                // Get connection info
                let pub_key_bytes = queued.public_key.0;
                let connection_tx = guard.connection_tx.clone();

                (
                    queued.public_key,
                    pub_key_bytes,
                    relay_addresses,
                    connection_tx,
                )
            };

            // Spawn connection task
            let inner_clone = inner.clone();
            let pub_key = PublicKey::from(pub_key_bytes);

            tokio::spawn(async move {
                let closest_nodes = (!relay_addresses.is_empty())
                    .then(|| relay_addresses.iter().map(Peer::from).collect());
                let connection_result = {
                    inner_clone
                        .read()
                        .unwrap()
                        .dht
                        .connect(pub_key, closest_nodes)
                };

                match connection_result.await {
                    Ok(connection) => {
                        debug!(?pk, "connection succeeded");
                        // Connection succeeded - update state
                        let should_emit = {
                            let mut guard = inner_clone.write().unwrap();
                            guard.pending_connects = guard.pending_connects.saturating_sub(1);

                            if let Some(peer_info) = guard.peers.get_mut(&pk) {
                                // TODO Maybe connection state should be an enum
                                peer_info.connected();
                            }

                            // Add to connection set
                            let add_result = guard.connections.add(pk, true);
                            add_result != AddResult::KeptExisting
                        }; // guard dropped here

                        if should_emit {
                            // Emit connection event (guard is dropped, safe to await)
                            let _ = connection_tx
                                .send(ConnectionEvent {
                                    connection,
                                    client: true,
                                    remote_public_key: pk,
                                })
                                .await;
                        }
                    }
                    Err(e) => {
                        debug!(?pk, ?e, "connection failed");
                        Self::handle_connection_failure(&inner_clone, pk);
                    }
                }
            });
        }
    }

    /// Handle a failed connection attempt
    fn handle_connection_failure(inner: &Arc<RwLock<SwarmInner>>, pk: IdBytes) {
        let mut guard = inner.write().unwrap();
        guard.pending_connects = guard.pending_connects.saturating_sub(1);

        // Get config value first before mutable peer borrow
        let auto_retry = guard.config.auto_retry;

        if let Some(peer_info) = guard.peers.get_mut(&pk) {
            peer_info.disconnected(); // Increments attempts, updates priority

            // Schedule retry if enabled and not banned
            let should_retry = auto_retry
                && peer_info.reconnecting
                && !peer_info.banned
                && peer_info.priority != Priority::VeryLow;

            if should_retry {
                peer_info.waiting = true;
                let attempts = peer_info.attempts;
                guard.retry_timer.schedule(RetryEntry::new(pk, attempts));
            }
        }
    }
}

/// Stream that yields all connections (client and server)
pub struct ConnectionStream {
    inner: Arc<RwLock<SwarmInner>>,
    connection_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ConnectionEvent>>>,
    server: Option<Server>,
}

impl Stream for ConnectionStream {
    type Item = Result<ConnectionEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        {
            let mut inner = self.inner.write().unwrap();
            _ = Stream::poll_next(Pin::new(&mut *inner), cx);
        };

        // Poll server for incoming connections first
        if let Some(ref mut server) = self.server {
            match Pin::new(server).poll_next(cx) {
                Poll::Ready(Some(Ok(connection))) => {
                    // For server connections, we need to track them
                    // Note: We don't have remote public key easily available here
                    // This is a limitation - we'd need to modify hdht to expose it
                    let remote_public_key = IdBytes([0; 32]); // Placeholder

                    {
                        let mut guard = self.inner.write().unwrap();
                        guard.connections.add(remote_public_key, false);
                    }

                    return Poll::Ready(Some(Ok(ConnectionEvent {
                        connection,
                        client: false,
                        remote_public_key,
                    })));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(e.into())));
                }
                Poll::Ready(None) => {
                    self.server = None;
                }
                Poll::Pending => {}
            }
        }

        // Poll client connection channel (non-blocking)
        if let Ok(mut rx) = self.connection_rx.try_lock() {
            match rx.poll_recv(cx) {
                Poll::Ready(Some(event)) => {
                    return Poll::Ready(Some(Ok(event)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Pending => {}
            }
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

struct PendingAnnounce {
    topic: IdBytes,
    announce: Announce,
}

impl PendingAnnounce {
    fn new(topic: IdBytes, announce: Announce) -> Self {
        Self { topic, announce }
    }
}

impl Future for PendingAnnounce {
    type Output = Result<IdBytes>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(res) = Pin::new(&mut self.announce).poll(cx) {
            return Poll::Ready(match res {
                Ok(_) => Ok(self.topic),
                Err(e) => Err(e.into()),
            });
        }
        Poll::Pending
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
        if inner.pending_announces.is_empty() && inner.pending_lookups.is_empty() {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

struct PendingLookup {
    topic: IdBytes,
    lookup: Lookup,
}

impl Stream for PendingLookup {
    type Item = (IdBytes, hyperdht::Result<Option<LookupResponse>>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.lookup).poll_next(cx) {
            Poll::Ready(Some(result)) => Poll::Ready(Some((self.topic, result))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct ServerFuture {
    swarm: Option<Arc<RwLock<SwarmInner>>>,
    dht_server_future: hyperdht::ServerFuture,
}

impl ServerFuture {
    fn new(
        swarm: Option<Arc<RwLock<SwarmInner>>>,
        dht_server_future: hyperdht::ServerFuture,
    ) -> Self {
        Self {
            swarm,
            dht_server_future,
        }
    }
}
impl Future for ServerFuture {
    type Output = Result<Server>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Drive the DHT while announcing
        if let Some(swarm) = self.swarm.as_ref() {
            let _ = Pin::new(&mut *swarm.write().unwrap()).poll_next(cx);
        }

        match Pin::new(&mut self.dht_server_future).poll(cx) {
            Poll::Ready(Ok(dht_server)) => {
                let swarm = self.swarm.take().expect("polled after completion");
                Poll::Ready(Ok(Server { dht_server, swarm }))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}
pub struct Server {
    swarm: Arc<RwLock<SwarmInner>>,
    dht_server: hyperdht::Server,
}
impl Stream for Server {
    type Item = Result<Connection>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        _ = Pin::new(&mut *self.swarm.write().unwrap()).poll_next(cx);
        Pin::new(&mut self.dht_server)
            .poll_next(cx)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_swarm() {
        let swarm = Swarm::default_config().await.unwrap();
        assert!(!swarm.destroyed());
        assert_eq!(swarm.connections_count(), 0);
    }

    #[tokio::test]
    async fn test_join_leave() {
        let swarm = Swarm::default_config().await.unwrap();
        let topic = IdBytes::random();

        assert!(!swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 0);

        swarm.join(topic, JoinOpts::Both).unwrap();
        assert!(swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 1);

        swarm.leave(&topic).unwrap();
        assert!(!swarm.has_topic(&topic));
        assert_eq!(swarm.topics_count(), 0);
    }

    #[tokio::test]
    async fn test_join_after_destroy_fails() {
        let swarm = Swarm::default_config().await.unwrap();
        swarm.destroy();

        let topic = IdBytes::random();
        let result = swarm.join(topic, JoinOpts::Client);
        assert!(result.is_err());
    }
}
