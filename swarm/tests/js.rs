use futures::{SinkExt, StreamExt};
use hypercore_handshake::CipherEvent;
use hyperswarm::{DhtConfig, JoinOpts, Swarm};
use test_utils::{Result, Testnet, rusty_nodejs_repl::wait};

macro_rules! timeout {
    ($fut:expr, $ms:expr) => {{ tokio::time::timeout(std::time::Duration::from_millis($ms), $fut).await }};
    ($fut:expr) => {
        timeout!($fut, 2000)
    };
}

#[tokio::test]
async fn rust_discovers_js_server() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    // JS: Create a swarm and announce on a topic
    let topic = tn.make_topic("test-topic").await?;
    tn.repl
        .run_tcp(format!(
            r#"
const Hyperswarm = require('hyperswarm');
const swarm = new Hyperswarm({{ bootstrap: ['{}'] }});
const topic = Buffer.from({:?});
await swarm.join(topic, {{ server: true, client: false }});
await swarm.flush();  // Wait for announce to complete
  "#,
            bs_addr, topic
        ))
        .await?;

    // Rust: Discover the JS peer
    let rust_swarm = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    rust_swarm.join(topic.into(), JoinOpts::Client)?;
    rust_swarm.flush().await?;

    // Wait for discovery
    wait!(100);

    assert!(
        dbg!(rust_swarm.peers_count()) > 0,
        "Should discover JS peer"
    );
    Ok(())
}

#[tokio::test]
async fn js_discovers_rust_server() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = tn.make_topic("test-topic").await?;

    // Rust: Create a swarm and announce on a topic
    let rust_swarm = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    rust_swarm.join(topic.into(), JoinOpts::Server)?;
    rust_swarm.flush().await?;

    // Wait for announce to propagate
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // JS: Use hyperdht directly to lookup peers (no connection attempt)
    tn.repl
        .run_tcp(format!(
            r#"
const DHT = require('hyperdht');
const dht = new DHT({{ bootstrap: ['{}'] }});
const topic = Buffer.from({:?});

const peers = [];
for await (const peer of dht.lookup(topic)) {{
  peers.push(...peer.peers);
}}

globalThis.peerCount = peers.length;
  "#,
            bs_addr, topic
        ))
        .await?;

    let peer_count: usize = tn.repl.get_name("globalThis.peerCount").await?;

    assert!(
        peer_count > 0,
        "JS should discover Rust peer via DHT lookup"
    );
    Ok(())
}

#[tokio::test]
async fn js_discovers_rust_peers() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    // JS: Create a swarm and announce on a topic
    let topic = tn.make_topic("test-topic").await?;
    tn.repl
        .run_tcp(format!(
            r#"
const Hyperswarm = require('hyperswarm');
swarm = new Hyperswarm({{ bootstrap: ['{}'] }});
const topic = Buffer.from({:?});
await swarm.join(topic, {{ server: true, client: false }});
await swarm.flush();  // Wait for announce to complete
  "#,
            bs_addr, topic
        ))
        .await?;

    // Rust: Discover the JS peer
    let mut rust_swarm = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    rust_swarm.join(topic.into(), JoinOpts::Client)?;
    rust_swarm.flush().await?;

    tokio::spawn(async move {
        loop {
            wait!(100);
            _ = rust_swarm.next().await;
        }
    });
    // Wait for discovery
    wait!(1000);

    let n_peers: usize = tn.repl.json_run_tcp("outputJson(swarm.peers.size)").await?;
    assert!(dbg!(n_peers) > 0, "Should discover JS peer");
    Ok(())
}

/// Rust swarm auto-connects to JS Hyperswarm server and exchanges messages
#[tokio::test]
async fn rust_swarm_connects_to_js_swarm_exchanges_messages() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = tn.make_topic("test-topic").await?;

    // JS: Create a Hyperswarm server that announces on topic
    tn.repl
        .run_tcp(format!(
            r#"
const Hyperswarm = require('hyperswarm');
js_swarm = new Hyperswarm({{ bootstrap: ['{}'] }});
const topic = Buffer.from({:?});

js_conn = deferred();
js_rx_data = deferred();

js_swarm.on('connection', (socket, peerInfo) => {{
    js_conn.resolve(socket);
    socket.on('data', (data) => {{
        js_rx_data.resolve(data.toString());
    }});
}});

await js_swarm.join(topic, {{ server: true, client: false }}).flushed();
"#,
            bs_addr, topic
        ))
        .await?;

    // Rust: Create swarm as client, should auto-discover and auto-connect
    let rust_swarm = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    rust_swarm.bootstrap().await?;

    let mut connections = rust_swarm.connections();
    rust_swarm.join(topic.into(), JoinOpts::Client)?;
    rust_swarm.flush().await?;

    // Wait for auto-connect
    let Some(Ok(event)) = timeout!(connections.next(), 5000)? else {
        panic!("Rust swarm should receive connection event");
    };
    let mut rust_conn = event.connection;

    // Rust sends to JS
    rust_conn.send(b"hello from rust".into()).await?;
    let js_rx: String = tn.repl.get_name("js_rx_data").await?;
    assert_eq!(js_rx, "hello from rust");

    // JS sends to Rust
    tn.repl
        .run_tcp("(await js_conn).write(Buffer.from('hello from js'))")
        .await?;

    let Some(CipherEvent::Message(msg)) = rust_conn.next().await else {
        panic!("Expected message from JS");
    };
    assert_eq!(msg.as_slice(), b"hello from js");

    Ok(())
}

/// JS swarm auto-connects to Rust swarm server and exchanges messages
#[tokio::test]
async fn js_swarm_connects_to_rust_swarm_exchanges_messages() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = tn.make_topic("test-topic").await?;

    // Rust: Create swarm as server, listen and announce
    let rust_swarm = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    rust_swarm.bootstrap().await?;

    let mut server = rust_swarm.listen().await?;
    rust_swarm.join(topic.into(), JoinOpts::Both)?;
    rust_swarm.flush().await?;

    // JS: Create a hyperswarm client that joins topic
    tn.repl
        .run_tcp(format!(
            r#"
const Hyperswarm = require('hyperswarm');
js_swarm = new Hyperswarm({{ bootstrap: ['{}'] }});
const topic = Buffer.from({:?});

js_conn = deferred();
js_rx_data = deferred();

js_swarm.on('connection', (socket, peerInfo) => {{
    js_conn.resolve(socket);
    socket.on('data', (data) => {{
        js_rx_data.resolve(data.toString());
    }});
}});

js_swarm.join(topic, {{ server: false, client: true }});
"#,
            bs_addr, topic
        ))
        .await?;

    // Rust server should receive the connection from JS
    let Some(Ok(mut rust_conn)) = timeout!(server.next())? else {
        panic!("Rust server should receive connection from JS");
    };

    // Rust sends to JS
    rust_conn.send(b"hello from rust server".into()).await?;
    let js_rx: String = tn.repl.get_name("js_rx_data").await?;
    assert_eq!(js_rx, "hello from rust server");

    // JS sends to Rust
    tn.repl
        .run_tcp("(await js_conn).write(Buffer.from('hello from js client'))")
        .await?;

    let Some(CipherEvent::Message(msg)) = rust_conn.next().await else {
        panic!("Expected message from JS");
    };
    assert_eq!(msg.as_slice(), b"hello from js client");

    Ok(())
}
