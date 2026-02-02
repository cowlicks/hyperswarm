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

DHT implementation that implements queries like lookup, announce, and unannounce. It facilitates finding and connecting to peers and establishing encrypted Noise streams.

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
- [x] `Dht::listen(keypair)` - Listen for incoming connections (returns `Server`)
- [x] `impl Clone for Dht` - Shares inner state, allows multiple handles
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

### Announcer
- [x] `Announcer` struct - Automatic periodic re-announcing for server mode
  - Holds own `Rpc` clone, performs all DHT operations directly
  - LOOKUP → ANNOUNCE commits → UNANNOUNCE retired relays → sleep/ping cycle
  - Three-generation relay tracking for graceful relay rotation
  - ~5 min cycle (100 iterations × 3s sleep), pings relays for health
  - Triggers refresh when active relays drop below 3
  - `Announcer::new(rpc, keypair, target)`, `.refresh()`, `.target()`, `.relay_addresses()`
  - Structured concurrency: poll to drive, stop polling to suspend, drop to stop

### Server
- [x] `Server` struct - Listens for incoming connections and maintains self-announcement
  - Wraps `Announcer` to keep `hash(publicKey)` announced on the DHT
  - Accepts incoming peer handshakes via keypair registration
  - `Dht::listen(keypair)` returns a `Server` (Stream of incoming connections)
  - Drives both the announcer and connection acceptance in a single poll loop

## Not Yet Implemented

- [ ] `on_peer_holepunch()` - NAT traversal (todo!())
- [ ] Relay address announcement (include relay_addresses in announce)
- [ ] Holepunching for NAT traversal

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
  - Creates a `PeerDiscovery` that runs lookup (client) or announce (server)
- [x] `Swarm::leave(topic)` - Leave a topic (drops PeerDiscovery, stops query)
- [x] `Swarm::has_topic()` / `Swarm::topics_count()`
- [x] `Swarm::flush()` - Wait for all discoveries to complete first round

### PeerDiscovery
- [x] `PeerDiscovery` struct - Manages discovery lifecycle for a single topic
  - State machine: Querying (Lookup or Announce) → Sleeping → Querying (refresh)
  - Automatic refresh every ~10 min + random jitter
  - `PeerDiscovery::new(topic, opts, dht, keypair)`
  - `.refresh()` - Restart query immediately
  - `.is_first_round_complete()` - Used by flush()
  - `impl Stream` yielding `LookupResponse` items continuously across refresh cycles

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
- [x] `discoveries: HashMap<IdBytes, PeerDiscovery>` - polled each tick
- [x] `handle_lookup_response()` - Process discovered peers
- [x] `auto_connect_job()` - Periodic connection attempts

## Not Yet Implemented

- [ ] Self-announce via Server/Announcer (so peers can findPeer(hash(publicKey)))
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
swarm.join(topic, JoinOpts::Client);    // lookup peers
swarm.join(topic, JoinOpts::Server);    // announce self
swarm.join(topic, JoinOpts::Both);      // both
swarm.leave(&topic);
swarm.has_topic(&topic) -> bool
swarm.topics_count() -> usize
swarm.flush().await?;                   // wait for first discovery round

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

## API Comparison: Rust vs JavaScript

There are some parts of the JavaScript API we don't implement because they don't make sense in a rust context. These usually have to do with lifecycle management.

* `destroy` methods like `Hyperswarm.destroy`, `Hyperdht.destroy`, `DhtRpc.destroy`.
  These are handled by simply dropping the value.
  There are some cases (like `Hyperdht.destroy`) where there may extra work (like an unannounce query).
  These can be done separately.

* `suspend`/`resume` methods like dht-rpc's `Io.suspend`, hyperdht's `Announcer.suspend`, `Hyperswarm.suspend`.
  We've implemented all async tasks using [structured concurrency](https://blog.yoshuawuyts.com/tree-structured-concurrency/),
  so work only happens when task is polled.
  There are no spawned background tasks.
  So to `suspend`, just don't poll, and to resume, poll.

### What JS Has That Rust Doesn't

| Feature | JS API | Status |
|---------|--------|--------|
| `joinPeer()` / `leavePeer()` | Direct peer targeting | Not implemented |
| `clear()` | Destroy all discoveries | Not implemented |
| `stats` | Connection statistics | Not implemented |
| `firewall` callback | Filter connections | Not implemented |
| `Announcer` | Auto re-announce | Done (hyperdht) |

### What Rust Has That JS Doesn't

| Feature | Rust API |
|---------|----------|
| `connect(pub_key)` | Connect by pubkey |
| `peer_handshake(key, addr)` | Direct address connect |
| `bootstrap()` | Manual DHT bootstrap |
| `local_addr()` | Get socket address |

---

## Next Steps

1. **Self-announce in swarm** - Wire Server/Announcer into Swarm so `join(Server)` self-announces on `hash(publicKey)`
2. **Holepunching** - NAT traversal via `on_peer_holepunch()`
3. **Relay address announcement** - Include relay_addresses in announce values
