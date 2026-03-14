//! Integration tests for hyperswarm

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use dht_rpc::IdBytes;
use futures::{Sink, SinkExt, Stream, StreamExt, join};
use hypercore_handshake::CipherEvent;
use hyperdht::Connection;
use hyperswarm::{DhtConfig, Error, JoinOpts, Swarm, SwarmConfig};
use test_utils::{Result, Testnet, rusty_nodejs_repl::wait};

use hypercore::{HypercoreBuilder, PartialKeypair, Storage};

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

#[tokio::test]
async fn replicate_with_hypercore() -> Result<()> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;
    let topic = IdBytes::random();

    let mut writer = HypercoreBuilder::new(Storage::new_memory().await.unwrap())
        .build()
        .await
        .unwrap();
    let public_key = writer.key_pair().public;
    let reader = HypercoreBuilder::new(Storage::new_memory().await.unwrap())
        .key_pair(PartialKeypair { public: public_key, secret: None })
        .build()
        .await
        .unwrap();

    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let (r1, r2) = tokio::join!(swarm_a.bootstrap(), swarm_b.bootstrap());
    r1?;
    r2?;

    // Grab connection streams before joining so no events are missed.
    let a_conns = swarm_a.connections().filter_map(|r| async move { r.ok().map(|e| e.connection) });
    let b_conns = swarm_b.connections().filter_map(|r| async move { r.ok().map(|e| e.connection) });

    swarm_a.join(topic, JoinOpts::Server);
    swarm_a.flush().await?;
    swarm_b.join(topic, JoinOpts::Client);
    swarm_b.flush().await?;

    let writer_rep = tokio::spawn(writer.replicator().with_connection_stream(a_conns));
    let reader_rep = tokio::spawn(reader.replicator().with_connection_stream(b_conns));

    writer.append(b"hello").await?;

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if reader.info().contiguous_length >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for replication");

    assert_eq!(reader.get(0).await.unwrap(), Some(b"hello".to_vec()));

    writer_rep.abort();
    reader_rep.abort();
    Ok(())
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
    swarm_a.join(topic, JoinOpts::Server);
    swarm_a.flush().await?;

    // Swarm B: client - discovers peers on topic
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_b.join(topic, JoinOpts::Client);
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
    swarm_a.join(topic, JoinOpts::Server);
    swarm_a.flush().await?;

    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let _server_b = swarm_b.connections();
    swarm_b.join(topic, JoinOpts::Server);
    swarm_b.flush().await?;

    // Client discovers
    let swarm_c = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    swarm_c.join(topic, JoinOpts::Client);
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
    swarm_a.join(topic, JoinOpts::Server);
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
    swarm_a.join(topic, JoinOpts::Server);
    swarm_a.flush().await?;

    // Swarm B: client with auto-connect enabled (default)
    let config_b = SwarmConfig::new(DhtConfig::default().add_bootstrap_node(bs_addr));
    let swarm_b = Swarm::with_config(config_b).await?;
    swarm_b.bootstrap().await?;

    // Join as client - should auto-discover peers
    swarm_b.join(topic, JoinOpts::Client);
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
    swarm_a.join(topic, JoinOpts::Server);
    swarm_a.flush().await?;

    // Get connection stream to receive auto-connect events
    let mut client_conns = swarm_b.connections();

    // Join as client - should auto-discover and auto-connect
    swarm_b.join(topic, JoinOpts::Client);
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
    swarm_a.join(topic, JoinOpts::Server);
    swarm_a.flush().await?;

    // Client joins topic - should discover server and auto-connect
    let mut client_conns = swarm_b.connections();
    swarm_b.join(topic, JoinOpts::Client);
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

    let client_pub_key = swarm_b.public_key();
    let server_task = tokio::spawn(async move {
        let Some(Ok(conn_event)) = timeout!(server_conns.next(), 1000).unwrap() else {
            panic!("Expected server connection");
        };
        assert!(!conn_event.client, "should be a server connection");
        assert!(
            conn_event.topics.is_empty(),
            "server connection should have empty topics"
        );
        // Server should know the client's public key from Noise handshake
        assert_eq!(
            conn_event.remote_public_key, client_pub_key,
            "server should have client's public key"
        );
        wait!(100);
    });

    _ = join!(client_task, server_task);
    Ok(())
}

async fn two_connected_swarms() -> Result<(Testnet, (Swarm, Swarm))> {
    let mut tn = Testnet::new().await?;
    let bs_addr = tn.bootstrap_addr().await?;

    let topic = IdBytes::random();

    let swarm_a = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
    let swarm_b = Swarm::new(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;

    swarm_a.bootstrap().await?;
    swarm_b.bootstrap().await?;

    // Server joins topic
    swarm_a.join(topic, JoinOpts::Server);
    swarm_a.flush().await?;

    // Client joins topic - should discover server and auto-connect
    swarm_b.join(topic, JoinOpts::Client);
    swarm_b.flush().await?;
    Ok((tn, (swarm_a, swarm_b)))
}
pub struct MessageCipher(pub Connection);

impl Stream for MessageCipher {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match Pin::new(&mut self.0).poll_next(cx) {
                Poll::Ready(Some(CipherEvent::Message(data))) => return Poll::Ready(Some(data)),
                Poll::Ready(Some(CipherEvent::HandshakePayload(_))) => continue,
                Poll::Ready(Some(CipherEvent::ErrStuff(_))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<Vec<u8>> for MessageCipher {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> std::result::Result<(), Self::Error> {
        Pin::new(&mut self.0).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

/// just doing the same thincg as hypercore_protocol's 'basic_protocol' test
#[tokio::test]
async fn protocol() -> Result<()> {
    use hypercore_protocol::{Event, Message, Protocol, schema};
    let (mut _tn, (swarm_i, swarm_r)) = two_connected_swarms().await?;

    let key = [3u8; 32];
    let i = tokio::spawn(async move {
        // get connection event
        let mut cstream = swarm_i.connections();
        let conn_event = cstream.next().await.unwrap().unwrap();

        // plug into Protocol
        let mut p = Protocol::new(Box::new(conn_event.connection));

        // get some events from protocol?
        assert!(matches!(p.next().await.unwrap()?, Event::Handshake(_)));
        p.open(key).await?;
        // NB: this is required. We need to a 'wake' in Protocol somewhere. k
        // that will trigger after the responder does an open
        wait!(1000);
        let Event::Channel(mut chan) = p.next().await.unwrap()? else {
            todo!()
        };
        chan.send(Message::Want(schema::Want {
            start: 0,
            length: 5,
        }))
        .await?;
        let pres = tokio::spawn(async move {
            assert!(matches!(p.next().await.unwrap().unwrap(), Event::Close(_)));
            println!("init RX close");
            //  TODO can't drop proto yet or the "Close" message will never get to the responder
            _ = timeout!(p.next(), 1000);
        });
        let cev = chan.next().await;
        assert!(matches!(
            cev.unwrap(),
            Message::Want(schema::Want {
                start: 10,
                length: 3
            })
        ));
        println!("init got chan message");
        chan.close().await?;
        println!("init sent close ");
        pres.await.unwrap();
        println!("init done close ");
        assert!(chan.closed());

        Ok::<_, Error>(())
    });

    let r = tokio::spawn(async move {
        // get connection event
        let mut cstream = swarm_r.connections();
        let conn_event = cstream.next().await.unwrap().unwrap();

        let mut p = Protocol::new(Box::new(conn_event.connection));

        // get some events from protocol?
        assert!(matches!(p.next().await.unwrap()?, Event::Handshake(_)));
        assert!(matches!(p.next().await.unwrap()?, Event::DiscoveryKey(_)));

        p.open(key).await?;
        let Event::Channel(mut chan) = p.next().await.unwrap()? else {
            todo!()
        };
        chan.send(Message::Want(schema::Want {
            start: 10,
            length: 3,
        }))
        .await?;
        let pres = tokio::spawn(async move {
            assert!(matches!(p.next().await.unwrap().unwrap(), Event::Close(_)));
            println!("resp RX close");
        });
        let cev = chan.next().await;
        assert!(matches!(
            cev.unwrap(),
            Message::Want(schema::Want {
                start: 0,
                length: 5
            })
        ));
        println!("resp got chan message");
        pres.await.unwrap();
        assert!(chan.closed());

        Ok::<_, Error>(())
    });

    let (ires, rres) = join!(i, r);
    ires??;
    rres??;

    Ok(())
}
