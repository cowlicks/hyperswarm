use futures::StreamExt;
use hyperswarm_dht::rpc::{DhtConfig, RpcDht, RpcDhtEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    if let Some(bootstrap) = std::env::args().nth(1) {
        println!("{}", bootstrap);

        let mut b = RpcDht::with_config(
            DhtConfig::default()
                .set_bootstrap_nodes(&[bootstrap])
                .register_commands(["values"])
                .bind("127.0.0.1:3402")
                .await
                .expect("Failed to create dht with socket"),
        )
        .await
        .expect("Failed to create dht with socket");

        b.bootstrap();

        loop {
            println!("looping b");
            if let Some(event) = b.next().await {
                match event {
                    RpcDhtEvent::RequestResult(res) => println!("b request result {:?}", res),
                    RpcDhtEvent::ResponseResult(res) => println!("b response result {:?}", res),
                    RpcDhtEvent::RoutingUpdated { peer, old_peer: _ } => {
                        println!("b routing updated {:?}", peer)
                    }
                    RpcDhtEvent::QueryResult { id: _, cmd, stats } => {
                        println!("b query result {} {:?}", cmd, stats)
                    }
                    RpcDhtEvent::Bootstrapped { .. } => {}
                }
            }
        }
    } else {
        let mut a = RpcDht::with_config(
            DhtConfig::default()
                .bind("127.0.0.1:3401")
                .await
                .expect("Failed to create dht with socket"),
        )
        .await
        .expect("Failed to create dht with socket");

        let work = tokio::task::spawn(async move {
            loop {
                if let Some(event) = a.next().await {
                    match event {
                        RpcDhtEvent::RequestResult(res) => println!("request result {:?}", res),
                        RpcDhtEvent::ResponseResult(_) => println!("response result"),
                        RpcDhtEvent::RoutingUpdated { .. } => println!("routing updated"),
                        RpcDhtEvent::QueryResult { .. } => println!("query result"),
                        RpcDhtEvent::Bootstrapped { .. } => {}
                    }
                }
            }
        });

        work.await?;
    }

    Ok(())
}
