use std::{
    future::Future,
    net::ToSocketAddrs,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use dht_rpc::{commit::Commit, io::InResponse, AsyncRpcDht, DhtConfig, IdBytes, QueryNext};
use futures::Stream;

use crate::{commands, queries::QueryResult, Result, DEFAULT_BOOTSTRAP};

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

    pub async fn lookup(&self, target: IdBytes, commit: Commit) -> Result<Lookup> {
        let query = self.rpc.query_next(commands::LOOKUP, target, None, commit);
        Ok(Lookup { query })
    }
}

pub struct Lookup {
    query: QueryNext,
}

pub struct PeersResponse {
    pub response: Arc<InResponse>,
    pub peers: Vec<crate::cenc::Peer>,
}

impl Stream for Lookup {
    type Item = Result<Option<PeersResponse>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        todo!()
    }
}

impl Future for Lookup {
    type Output = Result<QueryResult>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        todo!()
    }
}
