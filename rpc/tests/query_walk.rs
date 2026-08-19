//! A query walks the DHT on the closer nodes carried in each reply - that list is the only
//! thing that ever adds a candidate to the iterator. So a handler that replies without one
//! strands every query at its seed set, and on a network bigger than one hop that looks
//! exactly like a query that finished. `respond` therefore fills the list in when it isn't
//! given one, the same way JS dht-rpc's `req.reply()` does.

use std::{collections::HashSet, net::SocketAddr};

use dht_rpc::{Command, DhtConfig, ExternalCommand, IdBytes, QueryArgs, Rpc, RpcEvent};
use futures::StreamExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const STORAGE_NODES: usize = 12;
/// Replies to anything, so the only interesting thing about a reply is who sent it.
const ECHO: Command = Command::External(ExternalCommand(3));

#[tokio::test]
async fn a_custom_command_query_walks_past_its_seed_node() -> Result<()> {
    let bootstrap = Rpc::with_config(
        DhtConfig::default()
            .empty_bootstrap_nodes()
            .bind("127.0.0.1:0")?,
    )
    .await?;
    let bootstrap_addr = bootstrap.local_addr()?;
    // The first node has nobody to learn its own address from, so it is told.
    let SocketAddr::V4(v4) = bootstrap_addr else {
        panic!("bound a v4 address")
    };
    bootstrap.set_address(v4);

    let responders = tokio::select! {
        _ = serve(bootstrap.clone()) => unreachable!("a node's event loop never finishes"),
        result = scenario(bootstrap_addr) => result?,
    };

    assert!(
        responders.len() > 1,
        "the query never got past the one node it was seeded with - replies carried no \
         closer nodes, so the iterator had nowhere to go"
    );
    assert!(
        responders.len() >= STORAGE_NODES / 2,
        "the query only reached {} of {} nodes",
        responders.len(),
        STORAGE_NODES + 1
    );
    Ok(())
}

async fn scenario(bootstrap_addr: SocketAddr) -> Result<HashSet<SocketAddr>> {
    let mut nodes = Vec::with_capacity(STORAGE_NODES);
    for _ in 0..STORAGE_NODES {
        nodes.push(
            Rpc::with_config(
                DhtConfig::default()
                    .add_bootstrap_node(bootstrap_addr)
                    .bind("127.0.0.1:0")?,
            )
            .await?,
        );
    }

    // Deliberately *not* bootstrapped: an empty routing table means the query is seeded
    // with the bootstrap node and nothing else, so every other node it reaches it can only
    // have learned about from a reply.
    let querier = Rpc::with_config(
        DhtConfig::default()
            .add_bootstrap_node(bootstrap_addr)
            .bind("127.0.0.1:0")?,
    )
    .await?;

    // Everyone joins at once *while* everyone is answering. Bootstrapping them one at a
    // time instead would leave the ones already up unpolled, so their queries would sit
    // there timing out against nodes that are technically alive but nobody is driving.
    // The querier answers too: it is a node like any other, and once it has an id the
    // others route to it, so leaving it deaf just makes everyone wait out a timeout on it.
    let serving = futures::future::join_all(
        nodes
            .iter()
            .chain(std::iter::once(&querier))
            .map(|n| serve(n.clone())),
    );
    tokio::select! {
        _ = serving => unreachable!("a node's event loop never finishes"),
        result = async {
            for result in futures::future::join_all(nodes.iter().map(|n| n.bootstrap())).await {
                result?;
            }
            responders_to_one_query(&querier).await
        } => result,
    }
}

async fn responders_to_one_query(querier: &Rpc) -> Result<HashSet<SocketAddr>> {
    let mut query = querier.query(QueryArgs::new(ECHO, IdBytes::random()));
    let mut responders = HashSet::new();
    while let Some(reply) = query.next().await {
        responders.insert(reply.peer.addr);
    }
    let _ = query.await;
    Ok(responders)
}

/// Answer `ECHO` the lazy way - no closer nodes of our own - and let `respond` supply them.
async fn serve(mut rpc: Rpc) {
    while let Some(event) = rpc.next().await {
        if let RpcEvent::CustomRequest(request) = event {
            let _ = rpc.respond(&request.request, None, None, &request.peer);
        }
    }
}
