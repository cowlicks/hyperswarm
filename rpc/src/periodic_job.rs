use std::{pin::Pin, time::Duration};

use futures::task::{Context, Poll};
use wasm_timer::{Delay, Instant};

#[derive(Debug)]
pub struct PeriodicJob {
    pub interval: Duration,
    pub inner: Delay,
}

impl PeriodicJob {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            inner: Delay::new(interval),
        }
    }

    pub fn poll_now(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Poll::Ready(Ok(_)) = Delay::poll(Pin::new(&mut self.inner), cx) {
            let deadline = Instant::now() + self.interval;
            self.inner = Delay::new_at(deadline);
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    pub fn poll(&mut self, cx: &mut Context<'_>, now: Instant) -> Poll<()> {
        if let Poll::Ready(Ok(_)) = Delay::poll(Pin::new(&mut self.inner), cx) {
            let deadline = now + self.interval;
            self.inner = Delay::new_at(deadline);
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
