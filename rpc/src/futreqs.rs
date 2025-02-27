//! A future that represents a request.
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use wasm_timer::Instant;

use futures::{channel::oneshot, FutureExt};

use crate::Tid;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(32);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Request was cancelled")]
    Cancelled,
    #[error("Request timed out. timeout = [{0:?}]")]
    Timeout(Duration),
}

#[derive(Debug)]
pub struct RequestFuture<T> {
    rx: oneshot::Receiver<T>,
    started_at: Instant,
}

#[derive(Debug)]
pub struct RequestSender<T> {
    tx: oneshot::Sender<T>,
}

impl<T> RequestSender<T> {
    pub fn send(self, result: T) -> Result<(), T> {
        self.tx.send(result)
    }
}

pub fn new_request_channel<T>() -> (RequestSender<T>, RequestFuture<T>) {
    let (tx, rx) = oneshot::channel();
    let started_at = Instant::now();
    (RequestSender::<T> { tx }, RequestFuture { rx, started_at })
}

impl<T> Future for RequestFuture<T> {
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Poll the channel
        match self.rx.poll_unpin(cx) {
            Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(Error::Cancelled)),
            Poll::Pending => {
                if Instant::now().duration_since(self.started_at) > DEFAULT_REQUEST_TIMEOUT {
                    Poll::Ready(Err(Error::Timeout(DEFAULT_REQUEST_TIMEOUT)))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use futures::task::noop_waker;

    use super::*;

    // Function to check if a future is still pending
    fn is_pending<F: Future>(future: &mut F) -> bool {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Safety: we're just polling the future once and not moving it
        let pinned = unsafe { Pin::new_unchecked(future) };

        pinned.poll(&mut cx).is_pending()
    }

    #[tokio::test]
    async fn send_and_recv() -> Result<(), Box<dyn std::error::Error>> {
        let (tx, mut rx) = new_request_channel::<usize>();
        assert!(is_pending(&mut rx));

        let _ = tx.send(42);
        let x = rx.await?;
        assert_eq!(x, 42);
        Ok(())
    }
}
