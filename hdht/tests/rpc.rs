mod common;

use common::{Result, setup::Testnet};
use dht_rpc::{DhtConfig, Peer, commands, commit::Commit};

use crate::common::log;

macro_rules! rpc_setup {
    () => {{
        let mut tn = Testnet::new().await?;
        let bs_addr = tn.get_node_i_address(1).await?;
        let rpc =
            dht_rpc::AsyncRpcDht::with_config(DhtConfig::default().add_bootstrap_node(bs_addr))
                .await?;
        (tn, rpc)
    }};
}

// TODO move this to rpc crate. (Which requiress giving it it's own js-repl tests
#[tokio::test]
async fn test_async_rpc_request_ping() -> Result<()> {
    let (mut tn, rpc) = rpc_setup!();
    let _pub_key: Vec<u8> = tn
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
outputJson([...pub_key]);
",
        )
        .await?;
    let sport: usize = tn
        .repl
        .json_run_tcp("outputJson(server.dht.io.serverSocket._port)")
        .await?;
    // For FIND_NODE test
    //let idbytes: Vec<u8> = tn
    //    .repl
    //    .json_run_tcp("outputJson([...server.dht.id])")
    //    .await?;
    //let idbytes: [u8; 32] = idbytes.try_into().unwrap();
    //let command = commands::PING_NAT;
    //let command = commands::FIND_NODE;
    //let x = rpc.request(command, Some(idbytes), None, destination, None).await?;
    //let command = commands::DOWN_HINT;
    let command = commands::PING;
    let addr = format!("127.0.0.1:{sport}");
    let destination: Peer = addr.parse()?;
    let x = rpc.request(command, None, None, destination, None).await?;
    assert_eq!(x.request.command, command);
    Ok(())
}
#[tokio::test]
async fn test_async_rpc_query_find_node() -> Result<()> {
    let (mut tn, rpc) = rpc_setup!();
    let _pub_key: Vec<u8> = tn
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
outputJson([...pub_key]);
",
        )
        .await?;
    let sport: usize = tn
        .repl
        .json_run_tcp("outputJson(server.dht.io.serverSocket._port)")
        .await?;
    println!("SPORT {sport}");
    // For FIND_NODE test
    let idbytes: Vec<u8> = tn
        .repl
        .json_run_tcp("outputJson([...server.dht.id])")
        .await?;
    let idbytes: [u8; 32] = idbytes.try_into().unwrap();
    let command = hyperdht::commands::FIND_PEER;
    log();
    let x = rpc
        .query_next(command, idbytes.into(), None, Commit::No)
        .await?;
    dbg!(&x);
    //assert_eq!(x.request.command, command);
    Ok(())
}
