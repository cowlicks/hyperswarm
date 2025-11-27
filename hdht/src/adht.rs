use std::{
    future::Future,
    net::ToSocketAddrs,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use compact_encoding::CompactEncoding;
use dht_rpc::{commit::Commit, io::InResponse, AsyncRpcDht, DhtConfig, IdBytes, QueryNext};
use futures::Stream;
use tracing::instrument;

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

    pub fn lookup(&self, target: IdBytes, commit: Commit) -> Result<Lookup> {
        let query = self.rpc.query_next(commands::LOOKUP, target, None, commit);
        Ok(Lookup {
            query,
            topic: target,
            collected_responses: Vec::new(),
        })
    }
}

#[derive(Debug)]
pub struct Lookup {
    query: QueryNext,
    topic: IdBytes,
    collected_responses: Vec<Arc<InResponse>>,
}

#[derive(Debug)]
pub struct PeersResponse {
    pub response: Arc<InResponse>,
    pub peers: Vec<crate::cenc::Peer>,
}

impl Stream for Lookup {
    type Item = Result<Option<PeersResponse>>;

    #[instrument(skip_all)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.query).poll_next(cx).map(|x| {
            x.map(|response| {
                self.collected_responses.push(response.clone());
                PeersResponse::decode_response(response)
            })
        })
    }
}

impl Future for Lookup {
    type Output = Result<QueryResult>;

    #[instrument(skip_all)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut self.query).poll_next(cx) {
                Poll::Ready(Some(response)) => self.collected_responses.push(response),
                Poll::Ready(None) => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.query).poll(cx) {
            Poll::Ready(Ok(query_result)) => Poll::Ready(Ok(QueryResult {
                topic: self.topic,
                responses: std::mem::take(&mut self.collected_responses),
                query_id: query_result.query_id,
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl PeersResponse {
    /// `Ok(Some(Self))` if the response was successfully decoded,
    /// `Ok(None)` if the response doesn't have a value field,
    /// `Err(e)` if there was an error decoding.
    #[instrument(skip_all, err)]
    fn decode_response(response: Arc<InResponse>) -> Result<Option<PeersResponse>> {
        let Some(value) = &response.response.value else {
            return Ok(None);
        };
        let (peers, _rest): (Vec<crate::cenc::Peer>, &[u8]) =
            <Vec<crate::cenc::Peer> as CompactEncoding>::decode(value)?;
        debug_assert!(_rest.is_empty());
        Ok(Some(PeersResponse { response, peers }))
    }
}
