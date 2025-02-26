use std::{future::Future, pin::Pin, sync::Arc, task::Poll};

use dht_rpc::{
    io::{InResponse, IoHandler},
    query::QueryId,
    Command, ExternalCommand, IdBytes, PeerId, RequestFuture,
};
use futures::stream::FuturesUnordered;
use tracing::{error, warn};

use crate::{commands::LOOKUP, crypto::Keypair2, Result};

use super::UnannounceRequest;

#[derive(Debug)]
pub struct AunnounceClearInner {
    /// switched on when query is completed
    done: bool,
    pub topic: IdBytes,
    pub keypair: Keypair2,
    pub responses: Vec<Result<Arc<InResponse>>>,
    pub inflight_unannounces: FuturesUnordered<RequestFuture<Arc<InResponse>>>,
    pub inflight_announces: FuturesUnordered<RequestFuture<Arc<InResponse>>>,
}

impl AunnounceClearInner {
    pub fn new(topic: IdBytes, keypair: Keypair2) -> Self {
        Self {
            done: false,
            topic,
            keypair,
            responses: Default::default(),
            inflight_unannounces: Default::default(),
            inflight_announces: Default::default(),
        }
    }
    /// For each response send an unannounce
    pub fn inject_response(
        &mut self,
        io: &mut IoHandler,
        resp: Arc<InResponse>,
        query_id: QueryId,
    ) {
        if let (Some(token), Some(id), Command::External(ExternalCommand(LOOKUP))) =
            (&resp.response.token, &resp.valid_peer_id(), resp.cmd())
        {
            let destination = PeerId {
                addr: resp.peer.addr,
                id: *id,
            };

            let req = UnannounceRequest {
                keypair: self.keypair.clone(),
                topic: self.topic,
                token: *token,
                destination,
            };
            match io.start_send_next_fut_no_id(Some(query_id), req.into()) {
                Ok(fut) => self.inflight_unannounces.push(fut),
                Err(e) => error!("Erorr sending unannonuce: {e:?}"),
            }
        } else {
            warn!(
                resp.tid = resp.response.tid,
                resp.query_id = display(query_id),
                resp.token = debug(resp.response.token),
                resp.peer_id = debug(resp.valid_peer_id()),
                resp.cmd = display(resp.cmd()),
                "Other kind of response to lookup query"
            );
        };
    }
}

#[derive(Debug)]
pub struct AnnounceClearResult {
    pub responses: Vec<Result<Arc<InResponse>>>,
}

impl Future for AunnounceClearInner {
    type Output = Result<AnnounceClearResult>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        todo!()
    }
}
