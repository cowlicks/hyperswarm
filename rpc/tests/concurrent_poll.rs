//! A node must not lose incoming requests while it drives a query of its own.
//!
//! Every future handed out by [`Rpc`] - a query, a request, a bootstrap - drives the same
//! state machine, because that is the only way for anything to make progress. So a node
//! that is busy with its own query is still the node that has to answer other peers, and
//! an [`RpcEvent`] that comes out of the state machine while a query happens to be the
//! thing polling it belongs to whoever polls [`Rpc`] as a `Stream`, not to the query.
//! Dropping it strands the requester on a reply that never comes.

use std::{net::SocketAddr, time::Duration};

use dht_rpc::{
    Command, DhtConfig, ExternalCommand, IdBytes, Peer, QueryArgs, Rpc, RpcEvent, commands,
};
use futures::StreamExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const REQUESTS: usize = 5;
/// Any external command will do - the point is that it surfaces as an event.
const TEST_COMMAND: Command = Command::External(ExternalCommand(7));
/// Long enough for five localhost round trips, short enough to keep the test quick.
const HAMMER_TIME: Duration = Duration::from_millis(400);

#[tokio::test]
async fn incoming_requests_survive_a_concurrent_query() -> Result<()> {
    let bootstrap = Rpc::with_config(
        DhtConfig::default()
            .empty_bootstrap_nodes()
            .bind("127.0.0.1:0")?,
    )
    .await?;
    let bootstrap_addr = bootstrap.local_addr()?;

    let received = tokio::select! {
        _ = drive(bootstrap.clone()) => unreachable!("a node's event loop never finishes"),
        result = scenario(bootstrap_addr) => result?,
    };

    assert_eq!(
        received, REQUESTS,
        "a request that arrived while the node was querying was dropped instead of being \
         surfaced as an RpcEvent"
    );
    Ok(())
}

async fn scenario(bootstrap_addr: SocketAddr) -> Result<usize> {
    let server = joined_node(bootstrap_addr).await?;
    let client = joined_node(bootstrap_addr).await?;
    let server_addr = server.local_addr()?;

    // The server's state machine is polled *only* by its own queries for the whole window
    // the client is sending in. Nothing here polls the server as a `Stream` yet, so every
    // arriving datagram is read by a query poll - which is exactly the case that used to
    // lose events.
    tokio::select! {
        _ = query_continuously(&server) => unreachable!("the query loop runs until cancelled"),
        _ = tokio::time::timeout(HAMMER_TIME, hammer(&client, server_addr)) => {}
    }

    // Now play the part of the node's request handler and count what actually got through.
    let mut events = server.clone();
    let mut received = 0;
    while received < REQUESTS {
        match tokio::time::timeout(Duration::from_millis(500), events.next()).await {
            Ok(Some(RpcEvent::CustomRequest(_))) => received += 1,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
    Ok(received)
}

/// Keep a query in flight so that the node is never idle and never polled as a `Stream`.
async fn query_continuously(rpc: &Rpc) {
    loop {
        let mut query = rpc.query(QueryArgs::new(commands::FIND_NODE, IdBytes::random()));
        while query.next().await.is_some() {}
        let _ = query.await;
    }
}

/// Send requests the server has no handler for. They are never answered - all we care
/// about is whether the server sees them at all.
async fn hammer(rpc: &Rpc, server_addr: SocketAddr) {
    let destination = Peer::new(server_addr);
    let mut pending: futures::stream::FuturesUnordered<_> = (0..REQUESTS)
        .map(|i| {
            rpc.request(
                TEST_COMMAND,
                Some(IdBytes::random()),
                Some(vec![i as u8]),
                destination.clone(),
                None,
            )
        })
        .collect();
    while pending.next().await.is_some() {}
}

async fn joined_node(bootstrap_addr: SocketAddr) -> Result<Rpc> {
    let rpc = Rpc::with_config(
        DhtConfig::default()
            .add_bootstrap_node(bootstrap_addr)
            .bind("127.0.0.1:0")?,
    )
    .await?;
    rpc.bootstrap().await?;
    Ok(rpc)
}

async fn drive(mut rpc: Rpc) {
    while rpc.next().await.is_some() {}
}
