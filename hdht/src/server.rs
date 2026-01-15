use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use futures::Stream;
use tokio::sync::mpsc;

use crate::{Result, adht::DhtInner, next_router::connection::Connection};

pub struct Server {
    rx: mpsc::Receiver<Result<Connection>>,
    dht: Arc<RwLock<DhtInner>>,
}

impl Server {
    pub fn new(rx: mpsc::Receiver<Result<Connection>>, dht: Arc<RwLock<DhtInner>>) -> Self {
        Self { rx, dht }
    }
}

impl Stream for Server {
    type Item = Result<Connection>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll the DHT to drive the event loop and flush any pending responses
        while Pin::new(&mut *self.dht.write().unwrap())
            .poll_next(cx)
            .is_ready()
        {
            // keep loopin
        }

        // Check for new connections
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}
