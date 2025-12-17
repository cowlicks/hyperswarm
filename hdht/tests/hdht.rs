mod common;
use std::net::{SocketAddr, SocketAddrV4};

use dht_rpc::DhtConfig;
use futures::{SinkExt, StreamExt};
use hypercore_protocol::sstream::sm2::Event;
use hyperdht::HyperDht;

use common::{log, setup::Testnet, Result};

#[macro_export]
macro_rules! new_setup_rs_node_and_js_testnet {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let hdht = HyperDht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, hdht)
    }};
}

#[tokio::test]
async fn test_async_peer_handshake_to_connect_hdht() -> Result<()> {
    let (mut tn, hdht) = new_setup_rs_node_and_js_testnet!();
    tn.repl
        .run_tcp(
            "
server_rx_data = deferred();
SOCKET = null;

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(true)
        SOCKET = socket;
    });
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
",
        )
        .await?;

    let pub_key: [u8; 32] = tn.repl.json_run_tcp("outputJson([...pub_key]);").await?;

    // With RS do a find peer.
    log();
    let resp = hdht.find_peer(pub_key.into()).await?;
    dbg!(&resp);

    let known_good_addr: String = tn
        .repl
        .json_run_tcp(
            "
const { host, port } = server_node.address();
outputJson(`${host}:${port}`);",
        )
        .await?;
    let SocketAddr::V4(known_good_addr) = known_good_addr.parse()? else {
        todo!()
    };
    let mut conn = hdht.peer_handshake(pub_key.into(), known_good_addr).await?;
    _ = conn.send(b"HELLO".to_vec()).await;

    let _rx_msg: bool = tn.repl.get_name("server_rx_data").await?;
    tn.repl.print_until_settled().await?;
    tn.repl
        .run_tcp("console.log(await SOCKET.write(Buffer.from('from js')))")
        .await?;
    tn.repl.print_until_settled().await?;
    let Some(Event::Message(m)) = conn.next().await else {
        panic!()
    };
    assert_eq!(m, b"from js");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn peer_handshake_with_relay_hdht() -> Result<()> {
    let (mut tn, hdht) = new_setup_rs_node_and_js_testnet!();
    tn.repl
        .run_tcp(
            "
server_rx_data = deferred();
SOCKET = null;

server_node = testnet.nodes[testnet.nodes.length - 1];
server = server_node.createServer();

server.on('connection', socket => {
    socket.on('data', (data) => {
        server_rx_data.resolve(true)
        SOCKET = socket;
    });
});

pub_key  = server_node.defaultKeyPair.publicKey;;
await server.listen(server_node.defaultKeyPair);
",
        )
        .await?;

    let pub_key: [u8; 32] = tn.repl.json_run_tcp("outputJson([...pub_key]);").await?;

    // With RS do a find peer.
    log();
    let resp = hdht.find_peer(pub_key.into()).await?;

    let known_good_addr: String = tn
        .repl
        .json_run_tcp(
            "
const { host, port } = server_node.address();
outputJson(`${host}:${port}`);",
        )
        .await?;
    let known_good_addr: SocketAddrV4 = known_good_addr.parse()?;
    let mut conn = None;
    for r in &resp.responses {
        let addr = r.peer.ipv4_addr()?;
        if addr == known_good_addr {
            panic!()
        }

        match hdht.peer_handshake(pub_key.into(), addr).await {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(e) => eprintln!("BADBAD {e}"),
        }
    }

    let Some(_) = conn else {
        return Ok(());
    };

    let mut conn = hdht.peer_handshake(pub_key.into(), known_good_addr).await?;
    conn.send(b"HELLO".to_vec()).await?;

    let _rx_msg: bool = tn.repl.get_name("server_rx_data").await?;
    tn.repl.print_until_settled().await?;
    tn.repl
        .run_tcp("console.log(await SOCKET.write(Buffer.from('from js')))")
        .await?;
    tn.repl.print_until_settled().await?;
    let Some(Event::Message(m)) = conn.next().await else {
        panic!()
    };
    assert_eq!(m, b"from js");
    tn.repl.print_until_settled().await?;

    Ok(())
}
