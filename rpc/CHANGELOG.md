# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

### Changed

- A node no longer drops incoming requests while it is driving a query, request or
  bootstrap of its own. Those futures have to poll the same state machine to make
  progress, and used to discard the `RpcEvent`s that came out of it, so a
  `RpcEvent::CustomRequest` that arrived at the wrong moment was lost and the peer that
  sent it waited out its timeout. Events are now queued for whoever polls `Rpc` as a
  `Stream`, and every registered poller is woken rather than only the most recent one.

### Removed



## [0.0.2] - 2026-06-17

### Added

Initial release

### Changed

### Removed

<!-- next-url -->
[Unreleased]: https://github.com/cowlicks/hyperswarm/compare/dht-rpc-v0.0.2...HEAD
[0.0.2]: https://github.com/cowlicks/hyperswarm/compare/dht-rpc-v0.1.0...dht-rpc-v0.0.2
