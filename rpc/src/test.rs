use futures::StreamExt;
use std::{net::TcpListener, time::Duration};

use crate::{DhtConfig, Peer, Result, RpcEvent, RpcInner, cenc::validate_id};
pub fn free_port() -> Option<u16> {
    match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(listener) => {
            // Get the port number that was assigned
            match listener.local_addr() {
                Ok(addr) => Some(addr.port()),
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

#[tokio::test]
async fn wip_bootstrap() -> Result<()> {
    let confa: DhtConfig = Default::default();
    let confa = confa
        .bind(("127.0.0.1", dbg!(free_port().unwrap())))
        .unwrap();
    let mut a_node = RpcInner::with_config(confa).await?;

    a_node.bootstrap();
    let a_addr = a_node.local_addr()?;

    tokio::task::spawn(async move {
        loop {
            if let Some(a_evt) = a_node.next().await {
                println!("A = {a_evt:?}");
                match a_evt {
                    RpcEvent::ReadyToCommit { .. } => println!("ready to commit"),
                    RpcEvent::CustomRequest(_res) => println!("request result"),
                    RpcEvent::ResponseResult(_) => println!("response result"),
                    RpcEvent::RoutingUpdated { .. } => println!("routing updated"),
                    RpcEvent::QueryResult { .. } => println!("query result"),
                    RpcEvent::Bootstrapped { .. } => {}
                    RpcEvent::QueryResponse(_res) => println!("query response"),
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let confb: DhtConfig = Default::default();
    let confb = confb
        .bind(("127.0.0.1", dbg!(free_port().unwrap())))
        .unwrap();

    let confb = confb.set_bootstrap_nodes(&[a_addr]);
    let mut b_node = RpcInner::with_config(confb).await?;
    b_node.bootstrap();
    loop {
        if let Ok(Some(b_evt)) =
            tokio::time::timeout(Duration::from_millis(1500), b_node.next()).await
        {
            println!("B = {b_evt:?}");
            match b_evt {
                RpcEvent::CustomRequest(_res) => println!("request result"),
                RpcEvent::ResponseResult(_) => println!("response result"),
                RpcEvent::RoutingUpdated { .. } => println!("routing updated"),
                RpcEvent::ReadyToCommit { .. } => println!("ready to commit"),
                RpcEvent::QueryResult { .. } => {
                    println!("query result");
                    break;
                }
                RpcEvent::Bootstrapped { .. } => {}
                RpcEvent::QueryResponse(_res) => println!("query response"),
            }
        }
    }

    let mut nodes = vec![];
    for n in b_node.kbuckets.iter() {
        dbg!(&n);
        nodes.push(n);
    }
    dbg!(nodes.len());
    Ok(())
}

#[test]
fn test_validate_id() -> Result<()> {
    let id: [u8; 32] = [
        128, 153, 111, 213, 115, 62, 11, 125, 92, 62, 223, 183, 3, 135, 211, 39, 152, 41, 73, 55,
        160, 113, 55, 48, 114, 90, 50, 44, 201, 131, 192, 94,
    ];
    let from = Peer {
        id: None,
        referrer: None,
        addr: "188.166.28.20:60692".parse()?,
    };
    assert!(validate_id(&Some(id), &from).is_some());
    Ok(())
}
