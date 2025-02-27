//! A map where the values are futures.
//! You can Stream over the map and it will yield resolved futures and remove them form the map
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;
use pin_project::pin_project;

#[pin_project]
#[derive(Debug)]
pub struct FuturesMap<K: Ord + Clone, V: Future> {
    map: BTreeMap<K, Pin<Box<V>>>,
    ready: VecDeque<(K, V::Output)>,
}

impl<K: Ord + Clone, V: Future> FuturesMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> Option<Pin<Box<V>>> {
        self.map.insert(key, Box::pin(value))
    }
    pub fn get_mut(&mut self, key: &K) -> Option<&mut Pin<Box<V>>> {
        self.map.get_mut(key)
    }
}

impl<K: Ord + Clone, V: Future> Default for FuturesMap<K, V> {
    fn default() -> Self {
        Self {
            map: Default::default(),
            ready: Default::default(),
        }
    }
}

impl<K: Ord + Clone + std::fmt::Debug, V: Future> Stream for FuturesMap<K, V> {
    type Item = V::Output;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        // Check if there's a ready item to yield
        if let Some((_, output)) = this.ready.pop_front() {
            return Poll::Ready(Some(output));
        }

        // Process all futures to check for completion
        let mut completed = Vec::new();
        for (key, future) in this.map.iter_mut() {
            let pinned = Pin::new(future);
            match pinned.poll(cx) {
                Poll::Ready(output) => {
                    completed.push((key.clone(), output));
                }
                Poll::Pending => {}
            }
        }

        // Move completed futures' outputs to the ready queue and remove them from the map
        for (key, output) in completed {
            this.map.remove(&key);
            this.ready.push_back((key, output));
        }

        // Yield the next ready output if available
        if let Some((_, output)) = this.ready.pop_front() {
            Poll::Ready(Some(output))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use dht_rpc::{new_request_channel, RequestFuture};
    use futures::{task::noop_waker, StreamExt};
    use utils::Rand;

    // Function to check if a future is still pending
    fn is_pending<F: Stream>(future: &mut F) -> bool {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Safety: we're just polling the future once and not moving it
        let pinned = unsafe { Pin::new_unchecked(future) };

        pinned.poll_next(&mut cx).is_pending()
    }

    #[tokio::test]
    async fn foo() -> Result<(), Box<dyn std::error::Error>> {
        let rand = Rand::default();
        let mut map: FuturesMap<u16, RequestFuture<usize>> = FuturesMap::default();
        let counts = rand.shuffle((0..20).collect());

        let mut senders = vec![];
        for c in counts.iter() {
            let (tx, rx) = new_request_channel();
            senders.push(tx);
            map.insert(*c, rx);
        }

        assert!(is_pending(&mut map));
        let next = senders.pop().unwrap();
        next.send(42).unwrap();
        let Some(Ok(res)) = map.next().await else {
            panic!()
        };
        assert_eq!(res, 42);
        assert!(is_pending(&mut map));
        Ok(())
    }
}
