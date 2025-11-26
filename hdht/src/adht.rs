use std::net::ToSocketAddrs;

use dht_rpc::{AsyncRpcDht, DhtConfig};

use crate::{Result, DEFAULT_BOOTSTRAP};

pub struct Dht {
    rpc: AsyncRpcDht,
}

impl Dht {
    pub async fn with_config(mut config: DhtConfig) -> Result<Self> {
        if config.bootstrap_nodes.is_empty() {
            for addr_str in DEFAULT_BOOTSTRAP.iter() {
                if let Some(addr) = addr_str.to_socket_addrs()?.last() {
                    config.bootstrap_nodes.push(addr)
                }
            }
        }

        Ok(Self {
            rpc: AsyncRpcDht::with_config(config).await?,
        })
    }
}
