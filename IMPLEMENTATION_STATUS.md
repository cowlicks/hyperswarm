# Hyperswarm Rust Implementation Status

## Overview

This workspace contains Rust implementations of the Hyperswarm networking stack:

| Crate | JS Equivalent | Description |
|-------|---------------|-------------|
| `dht-rpc` (rpc/) | `dht-rpc` | Low-level DHT RPC protocol |
| `hyperdht` (hdht/) | `hyperdht` | DHT with peer discovery, announce, lookup |
| `hyperswarm` (swarm/) | `hyperswarm` | High-level swarm with auto-connect, topic management |

---

# dht-rpc (rpc/)

Low-level DHT RPC implementation providing the network transport layer.

## Completed ✓

- [x] UDP socket binding and message handling
- [x] Request/response correlation with transaction IDs
- [x] Node routing table with k-buckets
- [x] Bootstrap node discovery
- [x] Ping/pong for liveness checking
- [x] Query iteration (find closest nodes)
- [x] Token generation for write authorization
- [x] Compact encoding for messages
- [x] `ephemeral` mode (don't send node ID in responses)

## Public API

```rust
let rpc = Rpc::with_config(config).await?;
rpc.ping(addr).await?;
rpc.query(args);           // Returns Query stream
rpc.request(builder)?;     // Send single request
rpc.local_addr()?;
rpc.id() -> IdBytes;
```

---

# hyperdht (hdht/)

DHT implementation with peer discovery, connection establishment, and query handling.

## Completed ✓

### Core Features
- [x] `Dht` struct wrapping RPC with higher-level API
- [x] `Dht::bootstrap()` - Bootstrap into the DHT network
- [x] `Dht::lookup(topic)` - Find peers announcing on a topic
- [x] `Dht::find_peer(pubkey)` - Find a specific peer by public key
- [x] `Dht::announce(topic, keypair)` - Announce presence on a topic
- [x] `Dht::unannounce(topic, keypair)` - Remove announcement
- [x] `Dht::announce_clear(topic, keypair)` - Clear and re-announce
- [x] `Dht::connect(pubkey)` - Connect to peer by public key
- [x] `Dht::peer_handshake(args)` - Low-level connection to address
- [x] `Dht::listen(keypair)` - Listen for incoming connections (returns `ServerFuture`)
- [x] `Dht::start_listening(keypair)` - Register for connections without blocking on announce
- [x] `Dht::get_connection_stream(keypair)` - Get connection receiver only
- [x] `Dht::drive()` - Spawn background task to poll DHT (abort on drop)
- [x] `impl Stream for Dht` - Poll for DHT events

### Connection & Relay
- [x] Direct peer-to-peer connections via Noise IK handshake
- [x] Relay connections (client → relay → server)
- [x] `PeerHandshakeArgs` with `.relay_address()` for relay routing
- [x] Bidirectional data flow over encrypted connections
- [x] UDX stream transport

### Query Handlers (Responding to Other Nodes)
- [x] `on_peer_handshake()` - Handle incoming connection requests
- [x] `on_find_peer()` - Return peer record from router
- [x] `on_lookup()` - Return peer records for topic (up to 20)
- [x] `on_announce()` - Verify signature, store peer record
- [x] `on_unannounce()` - Verify signature, remove peer record
- [x] `PeerRecordCache` - Store peer records by topic (with capacity limit)
- [x] `PeerRouter` - Store self-announcing peers (target = hash(pubkey))

### JS Interop ✓
- [x] Rust client connects to JS server
- [x] JS client connects to Rust server
- [x] Announce/lookup interop both directions
- [x] Relay interop (RS→RS→JS, RS→JS→JS)

## Not Yet Implemented

- [ ] `on_peer_holepunch()` - NAT traversal (todo!())
- [ ] Relay address announcement (include relay_addresses in announce)
- [ ] Holepunching for NAT traversal
- [ ] `Announcer` - Automatic periodic re-announcing (see plan below)

## Test Coverage (hdht/tests/)

**adht.rs** - 19+ tests:
- `rsrs_server_tx_first` / `rsrs_client_tx_first` - Pure Rust peer handshake
- `js_announces_rs_looksup` / `rs_announces_js_looksup` - Announce/lookup interop
- `dht_lookup` - Lookup JS server by topic
- `js_server_listen_rs_find_peer` - Find peer interop
- `test_rs_connects_to_js` / `test_js_connects_to_rs` - Full connection interop
- `rs_unannounce` / `rs_announce_clear` - Unannounce functionality
- `rsrsrs_relay_connection_flow` - All-Rust relay
- `rsrsjs_relay_connection_flow` - RS→RS→JS relay
- `rsjsjs_relay_connection_flow` - RS→JS→JS relay

**query_handlers.rs** - Pure Rust swarm tests:
- `rs_swarm_announce_lookup` - Announce and lookup in Rust-only network
- `rs_swarm_find_peer` - Find peer by public key
- `rs_swarm_unannounce` - Unannounce flow

---

# hyperswarm (swarm/)

High-level swarm providing topic-based peer discovery and automatic connection management.

## Completed ✓

### Core Features
- [x] `Swarm` struct wrapping `Dht`
- [x] `Swarm::new(config)` / `Swarm::with_config(config)`
- [x] `Swarm::public_key()` / `Swarm::keypair()`
- [x] `Swarm::local_addr()`
- [x] `Swarm::bootstrap()` - Bootstrap the DHT

### Topic Discovery
- [x] `JoinOpts` - Client/Server/Both modes
- [x] `Swarm::join(topic, opts)` - Join topic for discovery
  - Client mode: starts lookup, discovers peers
  - Server mode: announces on topic AND self-announces on hash(pubkey)
- [x] `Swarm::leave(topic)` - Leave a topic
- [x] `Swarm::has_topic()` / `Swarm::topics_count()`
- [x] `Swarm::flush()` - Wait for pending announces/lookups

### Connection Management
- [x] `Swarm::connections()` - Stream of both client and server connections
  - Registers keypair for incoming connections
  - Returns `ConnectionStream` yielding `ConnectionEvent`
- [x] `Swarm::connect(pubkey)` - Connect to peer by public key
- [x] `Swarm::peer_handshake(pubkey, addr)` - Direct connection to address
- [x] `ConnectionEvent` - Contains connection, client flag, remote_public_key, topics
- [x] `ConnectionSet` - Track connections with duplicate resolution
- [x] Auto-connect to discovered peers (via `pending_connections`)

### Peer Tracking
- [x] `PeerInfo` - Track peer state, priority, topics, relay addresses
- [x] `Priority` levels (VeryLow → VeryHigh)
- [x] `PeerQueue` - Priority queue for connection ordering
- [x] `RetryTimer` - Exponential backoff for failed connections
- [x] `Swarm::peers_count()` / `Swarm::connections_count()`

### Internal Plumbing
- [x] `SwarmInner` with `impl Stream` for event loop
- [x] `pending_announces` / `pending_lookups` - FuturesUnordered
- [x] `handle_lookup_response()` - Process discovered peers
- [x] `auto_connect_job()` - Periodic connection attempts

## Not Yet Implemented

- [ ] Refresh cycle (re-lookup/re-announce every ~10min)
- [ ] `suspend()` / `resume()` - Pause/resume network activity
- [ ] `join_peer(pubkey)` / `leave_peer(pubkey)` - Explicit peer targeting
- [ ] `max_peers` limit (default: 64)
- [ ] Stats tracking (connects attempted/opened/closed)
- [ ] Firewall callback

## Public API

```rust
// Creation
let swarm = Swarm::new(DhtConfig::default()).await?;
let swarm = Swarm::with_config(SwarmConfig::new(dht_config)).await?;

// Identity
swarm.public_key() -> IdBytes
swarm.keypair() -> Keypair
swarm.local_addr() -> Result<SocketAddr>

// Discovery
swarm.join(topic, JoinOpts::Client)?;   // lookup peers
swarm.join(topic, JoinOpts::Server)?;   // announce self
swarm.join(topic, JoinOpts::Both)?;     // both
swarm.leave(&topic);
swarm.has_topic(&topic) -> bool
swarm.topics_count() -> usize
swarm.flush().await?;                   // wait for pending ops

// Connections
let mut conns = swarm.connections();    // ConnectionStream
swarm.connect(pub_key);                 // connect by pubkey
swarm.peer_handshake(pub_key, addr);    // direct connection

// Stats
swarm.peers_count() -> usize
swarm.connections_count() -> usize
```

## Test Coverage (swarm/tests/)

**Unit tests** (in lib.rs):
- PeerInfo priority calculations
- ConnectionSet duplicate resolution
- Swarm creation and basic operations

**integration.rs**:
- `server_announces_client_discovers` - Basic discovery flow
- `multiple_servers_discovered` - Find multiple peers
- `peers_connect_and_exchange_messages` - Full connection + data exchange
- `discovery_enqueues_peers_for_connection` - Auto-connect behavior
- `auto_connect_establishes_connection` - End-to-end auto-connect
- `connection_event_has_topics` - Verify topics and remote_public_key populated correctly

**js.rs** - JS interop:
- `rust_discovers_js_server` - Rust finds JS peer
- `js_discovers_rust_server` - JS finds Rust peer
- `rust_swarm_connects_to_js_swarm_exchanges_messages`
- `js_swarm_connects_to_rust_swarm_exchanges_messages`

---

# Planned Work

## Announcer (hyperdht)

Automatic periodic re-announcing for server mode. See JS `hyperdht/lib/announcer.js`.

### Behavior

- **Lifecycle:** `start()`, `stop()`, `suspend()`, `resume()`, `refresh()`
- **Background loop:** ~5 min cycle, ping relays, re-announce if needed
- **Three-generation relay tracking:** detect relay churn, unannounce from removed

### Proposed API

```rust
pub struct Announcer {
    dht: Arc<RwLock<DhtInner>>,
    keypair: Keypair,
    target: IdBytes,
    server_relays: [HashMap<SocketAddr, Peer>; 3],
    // ...
}

impl Announcer {
    pub fn new(dht, keypair) -> Self;
    pub async fn start(&mut self) -> Result<()>;
    pub async fn stop(&mut self) -> Result<()>;
    pub async fn suspend(&mut self) -> Result<()>;
    pub fn resume(&mut self);
    pub fn refresh(&self);
}
```

---

## API Comparison: Rust vs JavaScript

### What JS Has That Rust Doesn't

| Feature | JS API | Status |
|---------|--------|--------|
| `suspend()` / `resume()` | Pause network | Not implemented |
| `joinPeer()` / `leavePeer()` | Direct peer targeting | Not implemented |
| `clear()` | Destroy all discoveries | Not implemented |
| `stats` | Connection statistics | Not implemented |
| `firewall` callback | Filter connections | Not implemented |
| `Announcer` | Auto re-announce | Planned |

### What Rust Has That JS Doesn't

| Feature | Rust API |
|---------|----------|
| `connect(pub_key)` | Connect by pubkey |
| `peer_handshake(key, addr)` | Direct address connect |
| `bootstrap()` | Manual DHT bootstrap |
| `local_addr()` | Get socket address |

---

## Next Steps

1. **Announcer** - Implement automatic periodic re-announcing
2. **Refresh cycle** - Re-lookup/re-announce every ~10min
3. **suspend/resume** - Pause/resume network activity
