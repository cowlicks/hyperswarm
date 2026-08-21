//! A node's id is the hash of the address it is reachable on, and it cannot read that
//! address off its own socket - NAT sits in between, so what a node bound and what the
//! network reaches it on need not match. It learns the address from the `to` field peers
//! echo back, and until it has one it stays ephemeral: it claims no id, and peers keep it
//! out of their routing tables, because `validate_id` only accepts an id that really is
//! the hash of the address a message came from.

use std::net::{SocketAddr, SocketAddrV4};

use dht_rpc::{DhtConfig, IdBytes, Rpc, id_from_address};
use futures::StreamExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn a_joining_node_settles_on_the_id_of_its_own_address() -> Result<()> {
    let bootstrap = bootstrapper().await?;
    let bootstrap_addr = bootstrap.local_addr()?;

    tokio::select! {
        _ = drive(bootstrap.clone()) => unreachable!("a node's event loop never finishes"),
        result = async {
            let node = joined_node(bootstrap_addr).await?;

            assert!(
                !node.is_ephemeral(),
                "a node that has learned its address should stand behind an id"
            );
            assert_eq!(
                node.id(),
                id_from_address(v4(node.local_addr()?)),
                "the id a node settled on is not the hash of the address it is reachable on"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        } => result?,
    }
    Ok(())
}

#[tokio::test]
async fn a_settled_node_lands_in_the_routing_table_of_a_node_it_meets() -> Result<()> {
    let bootstrap = bootstrapper().await?;
    let bootstrap_addr = bootstrap.local_addr()?;

    let known = tokio::select! {
        _ = drive(bootstrap.clone()) => unreachable!("a node's event loop never finishes"),
        result = async {
            let node = joined_node(bootstrap_addr).await?;
            let node_addr = node.local_addr()?;

            // A node only becomes worth remembering once it has settled on an id, which
            // happens partway through its own bootstrap, so the introduction that actually
            // sticks is the round after that. Give the table a moment to catch up.
            let mut known = vec![];
            for _ in 0..40 {
                known = bootstrap.closer_nodes(node.id());
                if known.iter().any(|peer| peer.addr == node_addr) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Ok::<_, Box<dyn std::error::Error>>((known, node_addr))
        } => result?,
    };

    let (known, node_addr) = known;
    assert!(
        known.iter().any(|peer| peer.addr == node_addr),
        "the bootstrap node did not keep the node that just joined it; it knows {:?}",
        known.iter().map(|p| p.addr).collect::<Vec<_>>()
    );
    Ok(())
}

#[tokio::test]
async fn a_node_asked_to_stay_ephemeral_never_settles() -> Result<()> {
    let bootstrap = bootstrapper().await?;
    let bootstrap_addr = bootstrap.local_addr()?;

    tokio::select! {
        _ = drive(bootstrap.clone()) => unreachable!("a node's event loop never finishes"),
        result = async {
            let node = Rpc::with_config(
                DhtConfig::default()
                    .add_bootstrap_node(bootstrap_addr)
                    .set_ephemeral(true)
                    .bind("127.0.0.1:0")?,
            )
            .await?;
            node.bootstrap().await?;

            assert!(
                node.is_ephemeral(),
                "a node asked to stay ephemeral took up an id anyway"
            );
            assert_ne!(
                node.id(),
                id_from_address(v4(node.local_addr()?)),
                "an ephemeral node should not be identified by its address"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        } => result?,
    }
    Ok(())
}

#[tokio::test]
async fn an_id_pinned_by_the_caller_is_left_alone() -> Result<()> {
    let bootstrap = bootstrapper().await?;
    let bootstrap_addr = bootstrap.local_addr()?;
    let pinned = [7u8; 32];

    tokio::select! {
        _ = drive(bootstrap.clone()) => unreachable!("a node's event loop never finishes"),
        result = async {
            let mut config = DhtConfig::default()
                .add_bootstrap_node(bootstrap_addr)
                .bind("127.0.0.1:0")?;
            config.local_id = Some(pinned);
            let node = Rpc::with_config(config).await?;
            node.bootstrap().await?;

            assert_eq!(
                node.id(),
                IdBytes::from(pinned),
                "a caller that pinned an id had it overwritten"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        } => result?,
    }
    Ok(())
}

/// `bootstrap()` means "make sure I am on the network", so on a node that already is it
/// has nothing to do and should say so at once.
///
/// The case that bites is a bootstrap node: it has no bootstrap nodes of its own, so it
/// counts as bootstrapped from the moment it is built, and `RpcInner::bootstrap` then does
/// nothing at all - leaving the caller waiting on a reply that nobody was ever going to
/// send. It surfaces the moment anything brings a set of nodes up together without first
/// working out which of them are already up.
#[tokio::test]
async fn bootstrapping_a_node_that_is_already_bootstrapped_returns() -> Result<()> {
    let rpc = bootstrapper().await?;
    assert!(rpc.is_bootstrapped(), "a bootstrapper starts bootstrapped");

    // Twice, because the second call is the one with no work left to do either way.
    for round in 0..2 {
        tokio::time::timeout(std::time::Duration::from_secs(5), rpc.bootstrap())
            .await
            .unwrap_or_else(|_| panic!("bootstrap() round {round} never returned"))?;
    }
    Ok(())
}

/// The first node on a network has nobody to learn its address from, so it is told.
async fn bootstrapper() -> Result<Rpc> {
    let rpc = Rpc::with_config(
        DhtConfig::default()
            .empty_bootstrap_nodes()
            .bind("127.0.0.1:0")?,
    )
    .await?;
    let addr = v4(rpc.local_addr()?);
    rpc.set_address(addr);

    assert!(
        !rpc.is_ephemeral(),
        "a bootstrapper told its address should have settled immediately"
    );
    assert_eq!(rpc.id(), id_from_address(addr));
    Ok(rpc)
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

fn v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => panic!("bound a v6 address: {addr}"),
    }
}

/// Internal commands are answered from inside the state machine, so a node that only has
/// to reply to pings and find-nodes just needs polling.
async fn drive(mut rpc: Rpc) {
    while rpc.next().await.is_some() {}
}
