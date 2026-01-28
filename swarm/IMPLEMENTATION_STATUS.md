# Hyperswarm Rust Implementation Status

## Overview

Building a Rust `hyperswarm` crate on top of `hyperdht`, providing topic-based peer discovery and automatic connection management. This mirrors the JS hyperswarm library.

## Recent Progress (January 2026)

### hyperdht (hdht) - Major Milestones

#### Connection Relay Working ✓
Relay connections now work, allowing clients to connect to servers through intermediary relay nodes:
- `rsrsrs_relay_connection_flow` - Rust client → Rust relay → Rust server
- `rsrsjs_relay_connection_flow` - Rust client → Rust relay → JS server
- `rsjsjs_relay_connection_flow` - Rust client → JS relay → JS server

Key changes:
- `PeerHandshakeArgs` supports `.relay_address()` for specifying relay route
- Server handles `from_relay` messages correctly
- Relay nodes forward handshake messages between client and server

#### Server Announce-First Pattern ✓
- Server now announces on the DHT before accepting connections
- Fixes timing issues where clients couldn't find servers

#### Bidirectional RS ↔ JS Interop ✓
- `test_rs_connects_to_js` - Rust dht.connect() to JS server
- `test_js_connects_to_rs` - JS node.connect() to Rust server
- Data flows both directions successfully
- `rsrs_server_tx_first` / `rsrs_client_tx_first` - Pure Rust scenarios

#### Other hdht Features
- `Dht::next()` - Stream support for handling DHT events
- `unannounce()` - Remove announcements from DHT (tested)
- `announce_clear()` - Clear and re-announce with new keypair (tested)

---

## Original Plan

### Planned Crate Structure
```
hyperswarm/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Swarm type, public API
│   ├── error.rs            # Error types
│   ├── config.rs           # SwarmConfig (builder pattern)
│   ├── peer_info.rs        # PeerInfo + Priority enum
│   ├── peer_discovery.rs   # PeerDiscovery + sessions
│   ├── connection_set.rs   # ConnectionSet (dedup by pubkey)
│   ├── retry_timer.rs      # Exponential backoff (4 tiers)
│   └── priority_queue.rs   # ShuffledPriorityQueue
└── tests/
    └── integration.rs      # Rust + JS interop tests
```

### Planned Phases

**Phase 1: Foundation**
- Create crate, add to workspace
- error.rs, config.rs, peer_info.rs, connection_set.rs
- Basic Swarm wrapping Dht, listen() delegation

**Phase 2: Discovery**
- priority_queue.rs, peer_discovery.rs
- join()/leave() with DHT lookup/announce
- Refresh cycle (10min + jitter)

**Phase 3: Connection Management**
- retry_timer.rs with exponential backoff
- Auto-connect to discovered peers
- join_peer()/leave_peer()
- Duplicate connection resolution

**Phase 4: Polish**
- flush(), destroy(), suspend(), resume()
- Stats tracking
- JS interop tests

---

## What Has Been Done

### Crate Structure (Simplified)
```
hyperswarm/
├── Cargo.toml
└── src/
    ├── lib.rs              # Swarm, JoinOpts, Discovery
    ├── error.rs            # Error enum
    ├── peer_info.rs        # PeerInfo + Priority (with tests)
    └── connection_set.rs   # ConnectionSet (with tests)
```

### Completed Features

#### Phase 1: Foundation ✓
- [x] Created hyperswarm crate in workspace
- [x] error.rs - Error enum with thiserror
- [x] peer_info.rs - PeerInfo with Priority levels (VeryLow -> VeryHigh)
- [x] connection_set.rs - ConnectionSet with duplicate resolution
- [x] Basic Swarm struct wrapping Dht
- [x] listen() - returns Server stream for incoming connections

#### Phase 2: Discovery (Partial) ✓
- [x] JoinOpts (server/client modes)
- [x] join(topic, opts) - stores Discovery, starts lookup/announce
- [x] leave(topic) - removes Discovery
- [x] DHT lookup wired up - spawns task, adds discovered peers to HashMap
- [x] DHT announce wired up - spawns task to announce on topic
- [ ] peer_discovery.rs with session ref-counting (simplified inline)
- [ ] priority_queue.rs (not implemented)
- [ ] Refresh cycle (not implemented)

### Current Public API

```rust
// Creation
let swarm = Swarm::new(dht_config).await?;
let swarm = Swarm::default_config().await?;

// Identity
swarm.public_key() -> IdBytes
swarm.keypair() -> Keypair

// Server mode
let server = swarm.listen()?;  // Stream<Item=Result<Connection>>
swarm.listening() -> bool

// Topic discovery
swarm.join(topic, JoinOpts::client())?;   // lookup peers
swarm.join(topic, JoinOpts::server())?;   // announce self
swarm.join(topic, JoinOpts::both())?;     // both
swarm.leave(&topic)?;
swarm.has_topic(&topic) -> bool
swarm.topics_count() -> usize

// Peer tracking
swarm.peers_count() -> usize
swarm.connections_count() -> usize

// Lifecycle
swarm.destroyed() -> bool
swarm.destroy()
```

### Test Coverage

**hdht tests (19 tests in hdht/tests/adht.rs):**
- `rsrs_server_tx_first` / `rsrs_client_tx_first` - Pure Rust peer handshake
- `js_announces_rs_looksup` / `rs_announces_js_looksup` - Announce/lookup interop
- `dht_lookup` - Lookup JS server by topic
- `js_server_listen_rs_find_peer` - Find peer interop
- `dht_peer_handshake` - Direct peer handshake to JS
- `test_rs_connects_to_js` / `test_js_connects_to_rs` - Full connection interop
- `rs_unannounce` / `rs_announce_clear` - Unannounce functionality
- `rsrsrs_relay_connection_flow` - All-Rust relay
- `relay_handlers_basic` - Relay handler smoke test
- `rsrsjs_relay_connection_flow` - RS→RS→JS relay
- `rsjsjs_relay_connection_flow` - RS→JS→JS relay

**swarm tests (15 tests):**
- Unit tests for PeerInfo, Priority, ConnectionSet
- Basic integration tests for Swarm lifecycle

---

## What Remains To Be Done

### Phase 2: Discovery (Remaining)
- [ ] Refresh cycle - re-lookup/re-announce every 10min + jitter
- [ ] Track lookup tasks to cancel on leave()

### Phase 3: Connection Management
- [ ] priority_queue.rs - ShuffledPriorityQueue for connection ordering
- [ ] retry_timer.rs - Exponential backoff (S:1s, M:5s, L:15s, X:10min)
- [ ] Auto-connect to discovered peers using dht.connect()
- [ ] Connection queue with max_parallel limit (default: 3)
- [ ] max_peers limit (default: 64)
- [ ] join_peer(pubkey) / leave_peer(pubkey) - explicit peer targeting
- [ ] Handle connection success/failure, update PeerInfo
- [ ] Retry failed connections with backoff

### Phase 4: Polish
- [ ] flush() - wait for pending lookups/connections
- [ ] suspend() / resume() - pause/resume network activity
- [ ] SwarmEvent stream (Connection, Disconnection, PeersDiscovered)
- [ ] Stats tracking (connects attempted/opened/closed)
- [ ] unannounce on leave() when was server

### Future (Complex Networking)
- [x] **Relay support** - Basic relay connections working (see above)
- [ ] Relay address announcement (include relay_addresses in announce)
- [ ] Holepunching
- [ ] Firewall callback

---

## Files Reference

| File | Status | Description |
|------|--------|-------------|
| lib.rs | Done | Swarm, JoinOpts, Discovery, public API |
| error.rs | Done | Error enum |
| peer_info.rs | Done | PeerInfo + Priority with tests |
| connection_set.rs | Done | ConnectionSet with tests |
| config.rs | Removed | Simplified - config passed directly |
| peer_discovery.rs | Not created | Could extract Discovery logic |
| priority_queue.rs | Not created | Needed for connection ordering |
| retry_timer.rs | Not created | Needed for retry backoff |

---

## Dependencies

```toml
[dependencies]
hyperdht = { path = "../hdht" }
dht-rpc = { path = "../rpc" }
tokio = { version = "1.41.0", features = ["rt", "net", "sync"] }
futures = "0.3.5"
thiserror = "1.0.68"
tracing = "0.1.41"
rand = "0.7.3"
```

---

## API Comparison: Rust vs JavaScript

### What JS Has That Rust Doesn't

| Feature | JS API | Description |
|---------|--------|-------------|
| **Lifecycle** | `suspend()`, `resume()`, `destroy()` | Pause/resume network activity, explicit cleanup |
| **Direct Peer** | `joinPeer(publicKey)`, `leavePeer(publicKey)` | Target specific peers without topic |
| **Clear All** | `clear()` | Destroy all topic discoveries at once |
| **Statistics** | `stats` property | Connection counts (opened/closed/attempted) |
| **Firewall** | `firewall` callback | Filter incoming connections |
| **Relay** | `relayThrough` callback | Relay coordination |
| **Discovery Object** | `join()` returns `PeerDiscovery` | Has `flushed()`, `refresh()`, `destroy()` |

### What Rust Has That JS Doesn't

| Feature | Rust API | Description |
|---------|----------|-------------|
| **Direct Connect** | `connect(pub_key)` | Connect to peer by public key |
| **Low-level Handshake** | `peer_handshake(key, addr)` | Connect to specific address |
| **Explicit Bootstrap** | `bootstrap()` | Manually bootstrap DHT |
| **Local Address** | `local_addr()` | Get listening socket address |

### Client/Server Topic Association

**Key distinction in JS hyperswarm:**

| Connection Type | `peerInfo.client` | `peerInfo.topics` |
|-----------------|-------------------|-------------------|
| Client (we connect to them) | `true` | `[topic1, topic2, ...]` - topics from lookups |
| Server (they connect to us) | `false` | `[]` - empty, unknown |

- **Client mode** (`join(topic, { client: true })`): We do lookups, discover peers, and know which topics led us to them
- **Server mode** (`join(topic, { server: true })`): We announce, they find us, we don't know what topic brought them

**Rust implementation status:**

| Feature | Status | Notes |
|---------|--------|-------|
| `ConnectionEvent.client` flag | ✅ | Distinguishes initiator vs acceptor |
| `PeerInfo.topics` for discovered peers | ✅ | Topics added during lookup |
| Topics empty for server connections | ✅ | No PeerInfo created for incoming |
| Topics in ConnectionEvent | ❌ | Must lookup PeerInfo separately |

---

## DHT Query Handling (hdht)

### Current State

In `hdht/src/adht.rs`, `DhtInner::on_request()` handles incoming DHT queries:

```rust
match command {
    PEER_HANDSHAKE => self.on_peer_handshake(...)?,  // ✅ Implemented
    PEER_HOLEPUNCH => todo!(),                        // ❌ Not implemented
    FIND_PEER => { /* TODO */ }                       // ❌ Ignored (empty)
    LOOKUP => todo!(),                                // ❌ Not implemented
    ANNOUNCE => todo!(),                              // ❌ Not implemented
    UNANNOUNCE => todo!(),                            // ❌ Not implemented
}
```

### What Each Query Does (from JS `persistent.js`)

| Query | Purpose | JS Implementation |
|-------|---------|-------------------|
| **LOOKUP** | Find peers announced on a topic | Returns up to 20 peer records from `RecordCache` |
| **FIND_PEER** | Find a specific peer by pubkey hash | Returns single record from `_router` |
| **ANNOUNCE** | Store a peer record (with signature) | Verifies signature, stores in `RecordCache` or `_router` |
| **UNANNOUNCE** | Remove a peer record (with signature) | Verifies signature, removes from storage |
| **PEER_HOLEPUNCH** | NAT traversal coordination | Forwards holepunch messages between peers |

### Data Structures Needed

1. **RecordCache** - Stores peer records by topic hash
   - `add(topic_hash, public_key, record)` - Store a peer record
   - `get(topic_hash, limit)` - Get up to N peer records for a topic
   - `remove(topic_hash, public_key)` - Remove a peer record

2. **Router** - Stores "self-announcing" peers (where topic = hash(pubkey))
   - `set(key, { relay, record })` - Store a direct peer record
   - `get(key)` - Get the peer record
   - `delete(key)` - Remove the record

### Implementation Plan

#### Phase 1: Storage Layer
1. Create `PeerRecordCache` struct in hdht
   - Use `HashMap<IdBytes, Vec<PeerRecord>>` for topic → records
   - Add LRU eviction or TTL-based expiry
   - Max 20 records per topic (like JS)

2. Create `PeerRouter` struct
   - Use `HashMap<IdBytes, RouterEntry>` for pubkey_hash → record
   - Store relay address and encoded peer record

#### Phase 2: Query Handlers
1. **`on_lookup()`** - Query the `PeerRecordCache`, return encoded records
2. **`on_find_peer()`** - Query the `PeerRouter`, return single record
3. **`on_announce()`**:
   - Decode announce message
   - Verify signature using `crypto_sign_verify_detached`
   - If `target == hash(pubkey)`: store in `PeerRouter`
   - Else: store in `PeerRecordCache`
   - Reply with `{ token: false, closerNodes: false }`

4. **`on_unannounce()`**:
   - Decode unannounce message
   - Verify signature
   - Remove from appropriate storage
   - Reply

#### Phase 3: Holepunching (Future)
- `on_peer_holepunch()` - Forward holepunch messages between peers behind NAT

### Files to Create/Modify

| File | Changes |
|------|---------|
| `hdht/src/persistent.rs` | New: `PeerRecordCache`, `PeerRouter` |
| `hdht/src/adht.rs` | Add `on_lookup`, `on_find_peer`, `on_announce`, `on_unannounce` |
| `hdht/src/cenc.rs` | Add `Announce` message encoding if not present |

### Why This Matters

Without query handling, Rust DHT nodes are "selfish" - they can query the network but don't help route or store data for others. Implementing these handlers makes Rust nodes full DHT participants, improving network health and enabling pure-Rust DHT networks.

---

## Next Steps

1. **Test stability** - Ensure all relay tests pass consistently
2. **Auto-connect** - Wire up discovered peers to auto-connect via `dht.connect()`
3. **Connection management** - Implement retry backoff and connection limits
4. **Swarm events** - Expose connection/disconnection events to users
5. **DHT query handling** - Implement LOOKUP, FIND_PEER, ANNOUNCE, UNANNOUNCE handlers
