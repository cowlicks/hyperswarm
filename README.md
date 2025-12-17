# Hyperswarm
# ⚠️ WARNING 🚧 Work in Progress ⚒️Unstable 👷

Rust implementation of [dht-rpc](https://github.com/holepunchto/dht-rpc), [hyperdht](https://github.com/holepunchto/hyperdht), and  [hyperswarm](https://github.com/holepunchto/hyperswarm). See roadmap for progress.


The Kademlia implementation and logic is copied from [libp2-kad](https://github.com/libp2p/rust-libp2p/tree/e9952ea9e348fcc607dac0607ab532cc16208066/).

## Roadmap

### dht-rpc

This is basically done. Using it in hyperdht is driving further changes.
* [x] implement all query and request logic
* [ ] Rename `AsyncRpcDht` to `Rpc`. Don't export `RpcDht`

### hyperdht

* [ ] Remove `HyperDht` and `HyperDhtInner` in favor of `Dht`
* [x] Implement `Dht.connect`.
* [ ] Add support for relayed connections to `Dht.connect`. See [here](https://github.com/holepunchto/hyperdht/blob/main/docs/handshake.md) for more info.
* [ ] Add "server" functionality, allowing Rust to receive connections from JS hyperdht. JS docs [here](https://github.com/holepunchto/hyperdht?tab=readme-ov-file#await-serverlistenkeypair)

### hyperswarm

* [ ] finish hyperedht client & server modes
* [ ] implement `swarm.join`
## License

 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)
