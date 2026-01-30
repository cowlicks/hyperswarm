//! Integration tests for hyperswarm

use dht_rpc::IdBytes;
use futures::{SinkExt, StreamExt, join};
use hypercore_handshake::CipherEvent;
use hyperswarm::{DhtConfig, JoinOpts, Swarm, SwarmConfig};
use test_utils::{Result, Testnet, rusty_nodejs_repl::wait};

macro_rules! timeout {
    ($fut:expr, $ms:expr) => {{
        let connection_result =
            tokio::time::timeout(std::time::Duration::from_millis($ms), $fut).await;
        connection_result
    }};
    ($fut:expr) => {{
        let out = timeout!($fut, 300);
        out
    }};
}
/// Server announces and client discovers via lookup
#[tokio::test]
async fn server_announces_client_discovers() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Swarm A: server - listens and announces on topic
    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server_conns = swarm_a.connections();
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    // Swarm B: client - discovers peers on topic
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_b.join(topic, JoinOpts::Client)?;
    swarm_b.flush().await?;

    // B should have discovered A
    assert!(
        swarm_b.peers_count() > 0,
        "swarm_b should have discovered peers"
    );

    Ok(())
}

/// Multiple servers announce, client discovers all
#[tokio::test]
async fn multiple_servers_discovered() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Create two servers announcing on same topic
    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server_a = swarm_a.connections();
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server_b = swarm_b.connections();
    swarm_b.join(topic, JoinOpts::Server)?;
    swarm_b.flush().await?;

    // Client discovers
    let swarm_c = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_c.join(topic, JoinOpts::Client)?;
    swarm_c.flush().await?;

    // C should have found both A and B
    let peers = swarm_c.peers_count();
    assert!(
        peers >= 2,
        "should discover multiple peers, found {}",
        peers
    );

    Ok(())
}

/// Two peers connect and exchange messages
#[tokio::test]
async fn peers_connect_and_exchange_messages() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Swarm A: server - listens and announces on topic
    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_a.bootstrap().await?;
    let mut server_conns = swarm_a.connections();
    let server_addr = swarm_a.local_addr()?;
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    // Swarm B: client - connects to A directly using known address and public key
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_b.bootstrap().await?;
    let server_pub_key = swarm_a.keypair().public;

    // Run connect and accept in parallel
    let (mut client_conn, server_event) = join!(
        async {
            swarm_b
                .peer_handshake(server_pub_key.clone(), server_addr)
                .await
                .unwrap()
        },
        async { server_conns.next().await.unwrap().unwrap() }
    );
    let mut server_conn = server_event.connection;

    // Server sends first
    server_conn.send(b"hello from server".into()).await?;
    let CipherEvent::Message(msg) = client_conn.next().await.unwrap() else {
        panic!("Expected message from server");
    };
    assert_eq!(msg.as_slice(), b"hello from server");

    // Client sends back
    client_conn.send(b"hello from client".into()).await?;
    let CipherEvent::Message(msg) = server_conn.next().await.unwrap() else {
        panic!("Expected message from client");
    };
    assert_eq!(msg.as_slice(), b"hello from client");

    Ok(())
}

/// Test that discovery finds peers and enqueues them for connection
#[tokio::test]
async fn discovery_enqueues_peers_for_connection() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    // Swarm A: server - listens and announces on topic
    let config_a = SwarmConfig::new(DhtConfig::default().add_bootstrap_node(bs_addr));
    let swarm_a = Swarm::with_config(config_a).await?;
    swarm_a.bootstrap().await?;
    let _server_a = swarm_a.connections();
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    // Swarm B: client with auto-connect enabled (default)
    let config_b = SwarmConfig::new(DhtConfig::default().add_bootstrap_node(bs_addr));
    let swarm_b = Swarm::with_config(config_b).await?;
    swarm_b.bootstrap().await?;

    // Join as client - should auto-discover peers
    swarm_b.join(topic, JoinOpts::Client)?;
    swarm_b.flush().await?;

    // Should have discovered the server peer
    assert!(
        swarm_b.peers_count() > 0,
        "client should have discovered at least one peer"
    );

    Ok(())
}

/// Test that auto-connect actually establishes connections to discovered peers
#[tokio::test]
async fn auto_connect_establishes_connection() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    swarm_a.bootstrap().await?;
    swarm_b.bootstrap().await?;

    let mut server_conns = swarm_a.connections();
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    // Get connection stream to receive auto-connect events
    let mut client_conns = swarm_b.connections();

    // Join as client - should auto-discover and auto-connect
    swarm_b.join(topic, JoinOpts::Client)?;
    swarm_b.flush().await?;

    let a = tokio::spawn(async move {
        let Some(Ok(client_event)) = timeout!(client_conns.next()).unwrap() else {
            todo!()
        };
        let mut client_conn = client_event.connection;
        let Some(CipherEvent::Message(msg)) = client_conn.next().await else {
            todo!()
        };
        assert_eq!(msg, b"from server");
        client_conn.send(b"from client".into()).await.unwrap();
        wait!(100);
    });
    let b = tokio::spawn(async move {
        let Some(Ok(server_event)) = timeout!(server_conns.next(), 1000).unwrap() else {
            todo!()
        };
        let mut server_conn = server_event.connection;
        server_conn.send(b"from server".into()).await.unwrap();
        let Some(CipherEvent::Message(msg)) = server_conn.next().await else {
            todo!()
        };
        assert_eq!(msg, b"from client");
        wait!(100);
    });
    _ = join!(a, b);
    Ok(())
}

/// Test that ConnectionEvent contains the discovered topics for client connections
#[tokio::test]
async fn connection_event_has_topics() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    swarm_a.bootstrap().await?;
    swarm_b.bootstrap().await?;

    // Server joins topic
    let mut server_conns = swarm_a.connections();
    swarm_a.join(topic, JoinOpts::Server)?;
    swarm_a.flush().await?;

    // Client joins topic - should discover server and auto-connect
    let mut client_conns = swarm_b.connections();
    swarm_b.join(topic, JoinOpts::Client)?;
    swarm_b.flush().await?;

    // Both streams must be polled for auto-connect to complete
    let client_task = tokio::spawn(async move {
        let Some(Ok(conn_event)) = timeout!(client_conns.next(), 1000).unwrap() else {
            panic!("Expected client connection");
        };
        assert!(conn_event.client, "should be a client connection");
        assert!(
            conn_event.topics.contains(&topic),
            "connection event should contain the discovered topic, got {:?}",
            conn_event.topics
        );
        wait!(100);
    });

    let server_task = tokio::spawn(async move {
        let Some(Ok(conn_event)) = timeout!(server_conns.next(), 1000).unwrap() else {
            panic!("Expected server connection");
        };
        assert!(!conn_event.client, "should be a server connection");
        assert!(
            conn_event.topics.is_empty(),
            "server connection should have empty topics"
        );
        wait!(100);
    });

    _ = join!(client_task, server_task);
    Ok(())
}
