mod common;

use dht_rpc::{cenc::generic_hash, commit::Commit, DhtConfig, IdBytes};
use futures::{SinkExt, StreamExt};
use hypercore_protocol::sstream::sm2::Event;
use hyperdht::adht::Dht;

use common::{log, setup::Testnet, Result};

macro_rules! adht_setup {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let rpc = Dht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr)).await?;
        (tn, rpc)
    }};
}

#[tokio::test]
async fn adht_lookup() -> Result<()> {
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
    let res = lery.await?;
    dbg!(&res);
    Ok(())
}

#[tokio::test]
async fn adht_find_peer() -> Result<()> {
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
        dbg!(&e);
    }
    Ok(())
}

#[tokio::test]
async fn adht_peer_handshake() -> Result<()> {
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

    let port: u16 = tn.repl.get_name("server_addr").await?;
    tn.repl.print_until_settled().await?;
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
async fn adht_connect() -> Result<()> {
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
