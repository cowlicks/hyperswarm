//! A query walks the DHT on the closer nodes carried in each reply - that list is the only
//! thing that ever adds a candidate to the iterator. So a handler that replies without one
//! strands every query at its seed set, and on a network bigger than one hop that looks
//! exactly like a query that finished. `respond` therefore fills the list in when it isn't
//! given one, the same way JS dht-rpc's `req.reply()` does.
//!
//! This test is `#[ignore]`d because it cannot pass yet, for a reason underneath the one it
//! tests: **routing tables never populate**, so a handler has no closer nodes to send even
//! when it asks for them.
//!
//! `on_request` and `on_response` only call `add_node` for a peer whose `validate_id`
//! passes (`rpc/src/lib.rs`), and `validate_id` (`rpc/src/cenc.rs`) demands
//! `msg.id == generic_hash(sender's ip:port)`. But a node's own id is
//! `config.local_id.unwrap_or_else(thirty_two_random_bytes)` and nothing ever recomputes it
//! from the address it bound, so the check never passes. Only the query path
//! (`PeerState::Succeeded`) adds anyone, which is why a node ends up knowing just the peers
//! it queried, and a bootstrap node - which never runs a query - knows nobody at all.
//!
//! Deriving the id from the bound address in `Rpc::with_config` makes this test pass and
//! takes the bootstrap node from 0 known peers to 12. That is a change to what a node's
//! identity *is*, though, and a real node needs its *external* address for it (JS learns
//! that from the `to` field replies echo back), so it is left for its own change.

use std::{collections::HashSet, net::SocketAddr};

use dht_rpc::{Command, DhtConfig, ExternalCommand, IdBytes, QueryArgs, Rpc, RpcEvent};
use futures::StreamExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const STORAGE_NODES: usize = 12;
/// Replies to anything, so the only interesting thing about a reply is who sent it.
const ECHO: Command = Command::External(ExternalCommand(3));

#[tokio::test]
#[ignore = "blocked on node ids being random instead of derived from the node's address, \
            which leaves every routing table empty - see this file's module docs"]
async fn a_custom_command_query_walks_past_its_seed_node() -> Result<()> {
    let bootstrap = Rpc::with_config(
        DhtConfig::default()
            .empty_bootstrap_nodes()
            .bind("127.0.0.1:0")?,
    )
    .await?;
    let bootstrap_addr = bootstrap.local_addr()?;

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
        let node = Rpc::with_config(
            DhtConfig::default()
                .add_bootstrap_node(bootstrap_addr)
                .bind("127.0.0.1:0")?,
        )
        .await?;
        node.bootstrap().await?;
        nodes.push(node);
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

    let serving = futures::future::join_all(nodes.iter().map(|n| serve(n.clone())));
    tokio::select! {
        _ = serving => unreachable!("a node's event loop never finishes"),
        result = responders_to_one_query(&querier) => result,
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
