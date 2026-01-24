use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use futures::Stream;
use tokio::sync::mpsc;

use crate::{
    Result,
    adht::{Announce, DhtInner},
    next_router::connection::Connection,
};

pub struct Server {
    rx: mpsc::Receiver<Result<Connection>>,
    dht: Arc<RwLock<DhtInner>>,
}

/// Announces on the keypair, then resolves to a Server stream
pub struct ServerFuture {
    rx: Option<mpsc::Receiver<Result<Connection>>>,
    dht: Option<Arc<RwLock<DhtInner>>>,
    announcer: Announce,
}

impl ServerFuture {
    pub fn new(
        rx: mpsc::Receiver<Result<Connection>>,
        dht: Arc<RwLock<DhtInner>>,
        announcer: Announce,
    ) -> ServerFuture {
        ServerFuture {
            rx: Some(rx),
            dht: Some(dht),
            announcer,
        }
    }
}

impl Future for ServerFuture {
    type Output = Result<Server>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Drive the DHT while announcing
        if let Some(dht) = self.dht.as_ref() {
            let _ = Pin::new(&mut *dht.write().unwrap()).poll_next(cx);
        }

        match Pin::new(&mut self.announcer).poll(cx) {
            Poll::Ready(Ok(())) => {
                let rx = self.rx.take().expect("polled after completion");
                let dht = self.dht.take().expect("polled after completion");
                Poll::Ready(Ok(Server { rx, dht }))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Stream for Server {
    type Item = Result<Connection>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll the DHT to drive the event loop and flush any pending responses
        _ = Pin::new(&mut *self.dht.write().unwrap()).poll_next(cx);
        // Check for new connections
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}
