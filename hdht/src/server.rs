use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use futures::Stream;
use tokio::sync::mpsc;
use tracing::{debug, error};

use crate::{
    Result,
    adht::{Announce, DhtInner},
    next_router::connection::Connection,
};

pub struct Server {
    rx: mpsc::Receiver<Result<Connection>>,
    dht: Arc<RwLock<DhtInner>>,
    announcer: Option<Announce>,
}

impl Server {
    pub fn new(
        rx: mpsc::Receiver<Result<Connection>>,
        dht: Arc<RwLock<DhtInner>>,
        announcer: Announce,
    ) -> Self {
        Self {
            rx,
            dht,
            announcer: Some(announcer),
        }
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
            // TODO we should probably just do cx.waker().wakey_by_ref();
        }

        let finished = self
            .announcer
            .as_mut()
            .map(|mut a| {
                if let Poll::Ready(_res) = Pin::new(&mut a).poll(cx) {
                    debug!("Done announing on keypair");
                    _ = _res
                        .inspect_err(|e| error!(error =? e, "error announcing keypair for server"));
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false);
        if finished {
            self.announcer = None;
        }

        // Check for new connections
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}
