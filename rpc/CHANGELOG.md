# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

### Changed

### Removed



## [0.0.3] - 2026-08-24

### Added

- `DhtConfig::set_address` / `Rpc::set_address`, telling a node the address other nodes
  reach it on. A node's id is the hash of that address, and a bootstrap node has no peer to
  learn it from, so it has to be told - the equivalent of JS dht-rpc's
  `DHT.bootstrapper(port, host)` seeding its NAT sampler.
- `id_from_address`, exported so that "a node's id is the hash of its address" is
  checkable from outside the crate.

### Changed

- A node no longer drops incoming requests while it is driving a query, request or
  bootstrap of its own. Those futures have to poll the same state machine to make
  progress, and used to discard the `RpcEvent`s that came out of it, so a
  `RpcEvent::CustomRequest` that arrived at the wrong moment was lost and the peer that
  sent it waited out its timeout. Events are now queued for whoever polls `Rpc` as a
  `Stream`, and every registered poller is woken rather than only the most recent one.

- `Rpc::respond`'s `closer_nodes` argument now means what the same argument means in JS
  dht-rpc: `None` sends the closest nodes this node knows to the request's target, instead
  of sending an empty list. The peers in that list are the only candidates a requester's
  query iterator ever gains, so a handler that omitted them stranded every query at its
  seed set. Pass `Some(nodes)` to name peers explicitly, and `Some(vec![])` for a reply
  that is not part of a query walk.

- A node now derives its id from its own address rather than from random bytes. `validate_id`
  only accepts a claimed id that really is the hash of the address a message came from, so a
  random id never matched and `add_node` was never reached from `on_request`/`on_response`:
  routing tables stayed empty, and every query stopped at the node it was seeded with. A node
  now starts ephemeral, claiming no id, learns its address from the `to` field replies echo
  back, and settles once enough of them agree - rebuilding its routing table around the new
  id and bootstrapping once more so peers see it. A node asked to stay ephemeral never
  settles, and an id pinned through `config.local_id` is left alone.

- A query no longer contacts the node that started it. Peers hand back whoever they think is
  closest, which can include us; JS dht-rpc filters that out and this did not, so a node
  could stall its own query for a peer timeout waiting on itself.

- `DhtConfig::empty_bootstrap_nodes()` is now distinguishable from leaving the list unset, via
  `allow_default_bootstrap`. Crates layered on top (hyperdht) fill an empty list with their own
  defaults, so asking for no bootstrap nodes used to get you the public ones.

### Removed



## [0.0.2] - 2026-06-17

### Added

Initial release

### Changed

### Removed

<!-- next-url -->
[Unreleased]: https://github.com/cowlicks/hyperswarm/compare/dht-rpc-v0.0.3...HEAD
[0.0.3]: https://github.com/cowlicks/hyperswarm/compare/dht-rpc-v0.0.2...dht-rpc-v0.0.3
[0.0.2]: https://github.com/cowlicks/hyperswarm/compare/dht-rpc-v0.1.0...dht-rpc-v0.0.2
