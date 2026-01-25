use hyperswarm::{DhtConfig, JoinOpts, Swarm};
use test_utils::{Result, Testnet};

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

    // Wait for discovery
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
    let rust_swarm = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    rust_swarm.join(topic.into(), JoinOpts::Client)?;

    // Wait for discovery
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    let n_peers: usize = tn.repl.json_run_tcp("outputJson(swarm.peers.size)").await?;
    dbg!(n_peers);
    assert!(dbg!(n_peers) > 0, "Should discover JS peer");
    Ok(())
}
