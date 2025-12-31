use std::{net::ToSocketAddrs, sync::OnceLock};

use futures::StreamExt;

use crate::{DEFAULT_BOOTSTRAP, DhtConfig, Peer, RpcInner};

use super::RpcDhtEvent;

#[allow(unused)]
pub fn log() {
    static START_LOGS: OnceLock<()> = OnceLock::new();
    START_LOGS.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_line_number(true)
            .without_time()
            // Reads `RUST_LOG` environment variable
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    });
}

#[tokio::test]
#[ignore] // slow??? also should be integration test
async fn bootstrap() -> crate::Result<()> {
    let conf = DhtConfig::default()
        .add_bootstrap_node(DEFAULT_BOOTSTRAP[0].to_socket_addrs()?.last().unwrap());

    let mut rpc = RpcInner::with_config(conf).await?;

    rpc.bootstrap();
    let mut i = 0;
    loop {
        if let Some(RpcDhtEvent::QueryResult { .. }) = rpc.next().await {
            break;
        };
        dbg!(i);
        i += 1;
    }
    println!("# events {i}");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn ping() -> crate::Result<()> {
    let conf = DhtConfig::default()
        .add_bootstrap_node(DEFAULT_BOOTSTRAP[0].to_socket_addrs()?.last().unwrap());

    let mut rpc = RpcInner::with_config(conf).await?;

    rpc.bootstrap();
    let mut i = 0;
    loop {
        if let Some(RpcDhtEvent::QueryResult { .. }) = rpc.next().await {
            break;
        };
        i += 1;
    }
    log();

    rpc.ping(&Peer {
        addr: "170.187.185.104:60531".parse()?,
        id: None,
        referrer: None,
    });
    println!("PING_DONE");

    loop {
        let x = rpc.next().await;
        dbg!(x);
        dbg!(i);
        i += 1;
    }
}
