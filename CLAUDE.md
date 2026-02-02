This is a Rust workspace where we are re-implementing some JavaScript libraries used for peer discovery on a peer-to-peer network. There are 3 JavaScript libraries that correspond to 3 Rust crates.


The JavaScript libraries are located in `./test_utils/js`.

They are:
* The JavaScript package 'dht-rpc' in `test_utils/js/dht-rpc` which corresponds to the Rust crate 'dht-rpc' in `./rpc`
* The JavaScript package 'hyperdht' in `test_utils/js/hyperdht` which corresponds to the Rust crate 'hyperdht' in `./hdht`
* The JavaScript package 'hyperswarm' in `test_utils/js/hyperswarm` which corresponds to the Rust crate 'hyperswarm' in `./swarm`


The dependencies structure is: hyperswarm -> hyperdht -> dht-rpc.

dht-rpc is the innermost library. It handles low-level DHT queries and IO.
Hyperdht builds on dht-rpc, it provides an interface for making announcements about "topics" on the DHT,
and creating peer-to-peer connections.
Hyperswarm builds on hyperdht. It provides a simple interface to automatically connect to other peers interested in a "topic".


## Building and testing

Use `cargo clippy` for a quick compilation and lint check and `cargo test` to run all tests.
You can target a specific crate with e.g. `cargo test -p hyperdht` or `cargo test -p hyperswarm`.

## Integration tests with JavaScript (rusty_nodejs_repl)

Integration tests use the `rusty_nodejs_repl` crate to spin up a Node.js REPL from within Rust tests.
This lets us run the original JavaScript libraries side-by-side with the Rust implementations to verify interoperability.

Utils for the pattern live in `test_utils/src/lib.rs` which provides `make_repl()` which creates a configured Node.js REPL with the JS packages pre-loaded.
Example tests are in `hdht/tests/adht.rs`.

Node.js and npm must be available on the system to run integration tests.

## Structured concurrency

In Rust we are using the "Structured Concurrency" pattern. We don't spawn background tasks (like with `tokio::spawn`).
This means we don't need methods like `suspend`/`resume`, because work only happens when we "poll" tasks.
So to "suspend", just don't poll, and to "resume", just poll.

