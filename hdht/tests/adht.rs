mod common;

use dht_rpc::{cenc::generic_hash, commit::Commit, DhtConfig, IdBytes};
use futures::{SinkExt, StreamExt};
use hypercore_protocol::sstream::sm2::Event;
use hyperdht::{adht::Dht, Keypair};

use common::{log, setup::Testnet, Result};

macro_rules! adht_setup {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let rpc = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, rpc)
    }};
}

/// Check that Rust's lookup works. The steps:
/// js does an announce with a `topic` and `keypair`
/// rs does a lookup for `topic`. Then checks the resulting keys found match `keypair`
#[tokio::test]
async fn js_announces_rs_looksup() -> Result<()> {
    let (mut tn, dht) = adht_setup!();

    let topic = tn.make_topic("hello").await?;

    // with js announc on topic with the node's default keypair
    let _res = tn
        .repl
        .run_tcp(
            "
ann_node = testnet.nodes[testnet.nodes.length - 1];
query = await ann_node.announce(topic, ann_node.defaultKeyPair);
await query.finished();
",
        )
        .await?;

    // with RS do a lookup
    let mut query = dht.lookup(topic.into(), Commit::No)?;
    let mut rs_lookup_keys = vec![];
    while let Some(Ok(msg)) = query.next().await {
        println!("{msg:?}");
        if let Some(msg) = msg {
            rs_lookup_keys.extend(msg.peers);
        }
    }

    // get the public key js announced with
    let js_pk: Vec<u8> = tn
        .repl
        .json_run_tcp("outputJson([...ann_node.defaultKeyPair.publicKey])")
        .await?;
    // check js pub key matches the ones we found in rust
    assert!(!rs_lookup_keys.is_empty());
    for p in rs_lookup_keys {
        assert_eq!(p.public_key.as_slice(), js_pk);
    }
    Ok(())
}
/// Test Rust's announce. The steps:
/// rs does announce for a `topic` with `keypair`
/// js does loookup, and we check that resulting publick keys match `keypair`
#[tokio::test]
async fn rs_announces_js_looksup() -> Result<()> {
    let (mut testnet, dht) = adht_setup!();

    let topic = testnet.make_topic("hello").await?;
    let keypair = Keypair::default();
    dht.announce(topic.into(), keypair.clone(), vec![]).await?;

    // Run announce to completion
    // do lookup in js.
    let found_pk_js = testnet.get_pub_keys_for_lookup().await?;

    assert!(!found_pk_js.is_empty());
    for pk in found_pk_js {
        assert_eq!(keypair.public.as_slice(), pk);
    }
    Ok(())
}

#[tokio::test]
async fn dht_lookup() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let pub_key: Vec<u8> = tn
        .repl
        .run_tcp(
            "
server_addr = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
outputJson([...pub_key]);
",
        )
        .await?;
    let target = IdBytes(generic_hash(&pub_key));

    let mut lery = dht.lookup(target, Commit::No)?;
    while let Some(x) = lery.next().await {
        println!("{x:?}");
    }
    let _res = lery.await?;
    Ok(())
}

#[tokio::test]
async fn dht_find_peer() -> Result<()> {
    log();
    let (mut tn, dht) = adht_setup!();
    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_addr = deferred();
server_rx_data = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(data.toString());
        SOCKET = socket;
    });
});
pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
outputJson([...pub_key]);
",
        )
        .await?;

    dht.boostrap().await?;
    let mut q = dht.find_peer(pub_key.into())?;
    while let Some(e) = q.next().await {
        // TODO check results against something
        dbg!(&e);
    }
    Ok(())
}

#[tokio::test]
async fn dht_peer_handshake() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_addr = deferred();
server_rx_data = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(data.toString());
        SOCKET = socket;
    });
});
pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
outputJson([...pub_key]);
",
        )
        .await?;

    dht.boostrap().await?;

    let port: u16 = tn.repl.get_name("server_addr").await?;
    let dest = format!("127.0.0.1:{port}").parse()?;
    let mut conn = dht.peer_handshake(pub_key.into(), dest)?.await?;
    conn.send(b"from rust".into()).await?;
    let msg: String = tn.repl.get_name("server_rx_data").await?;
    assert_eq!(msg, "from rust");

    tn.repl
        .run_tcp("await SOCKET.write(Buffer.from('from js'))")
        .await?;
    let Some(Event::Message(rx_from_js)) = conn.next().await else {
        todo!()
    };
    assert_eq!(String::from_utf8_lossy(&rx_from_js), "from js");
    Ok(())
}

#[tokio::test]
async fn test_dht_connect() -> Result<()> {
    let (mut tn, dht) = adht_setup!();
    let pub_key: [u8; 32] = tn
        .repl
        .json_run_tcp(
            "
server_addr = deferred();
server_rx_data = deferred();


server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();
server.on('listening', () => {
    server_addr.resolve(server.address().port)
});

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(data.toString());
        SOCKET = socket;
    });
});
pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
outputJson([...pub_key]);
",
        )
        .await?;

    dht.boostrap().await?;
    let mut conn = dht.connect(pub_key.into()).await?;
    conn.send(b"from rust".into()).await?;
    let msg: String = tn.repl.get_name("server_rx_data").await?;
    assert_eq!(msg, "from rust");

    tn.repl
        .run_tcp("await SOCKET.write(Buffer.from('from js'))")
        .await?;
    let Some(Event::Message(rx_from_js)) = conn.next().await else {
        todo!()
    };
    assert_eq!(String::from_utf8_lossy(&rx_from_js), "from js");
    Ok(())
}

/// Test Rust's unannounce. The steps:
/// rs does announce
/// js does lookup, check topic is found with correct pk
/// rs does unannounce
/// js does a lookup, check no results found
#[tokio::test]
async fn tttttest_rs_unannounce() -> Result<()> {
    let (mut tn, mut dht) = adht_setup!();
    let topic = tn.make_topic("hello").await?;
    let keypair = Keypair::default();
    log();
    // announce our rust node with `topic` and `keypair`
    dht.announce(topic.into(), keypair.clone(), vec![]).await?;

    // with js do a lookup and get pubkeys
    let found_pk_js = tn.get_pub_keys_for_lookup().await?;
    // get result for js and show it matches the RS keypair above
    assert_eq!(keypair.public.as_slice(), found_pk_js[0]);

    // Do the unannounce
    dht.unannounce(topic.into(), keypair).await?;

    // Do a lookup for a the topic again
    let found_pk_js = tn.get_pub_keys_for_lookup().await?;
    // assert no keys found for the topic
    assert_eq!(found_pk_js.len(), 0);
    Ok(())
}
