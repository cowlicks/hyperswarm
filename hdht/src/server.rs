use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use dht_rpc::{IdBytes, generic_hash};
use futures::Stream;
use tokio::sync::mpsc;

use crate::{
    Keypair, Result, adht::DhtInner, announcer::Announcer, next_router::connection::Connection,
};

pub struct Server {
    rx: mpsc::Receiver<Result<Connection>>,
    dht: Arc<RwLock<DhtInner>>,
    announcer: Announcer,
}

impl Server {
    pub fn new(
        rx: mpsc::Receiver<Result<Connection>>,
        keypair: Keypair,
        dht: Arc<RwLock<DhtInner>>,
    ) -> Self {
        let target = IdBytes(generic_hash(&*keypair.public));
        let announcer = Announcer::new(dht.read().unwrap().get_rpc(), keypair, target);
        Self { rx, dht, announcer }
    }
}

impl Stream for Server {
    type Item = Result<Connection>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        _ = Pin::new(&mut *self.dht.write().unwrap()).poll_next(cx);
        _ = Pin::new(&mut self.announcer).poll_next(cx);
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}
