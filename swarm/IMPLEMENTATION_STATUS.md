# Hyperswarm Rust Implementation Status

## Overview

Building a Rust `hyperswarm` crate on top of `hyperdht`, providing topic-based peer discovery and automatic connection management. This mirrors the JS hyperswarm library.

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
- 15 tests passing
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
- [ ] JS interop tests

### Future (Complex Networking)
- [ ] Relay support (relay_addresses in announce)
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
