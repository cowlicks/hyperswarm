use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use dht_rpc::{Commit, IdBytes};
use futures::Stream;
use hyperdht::{
    Keypair,
    adht::{Announce, Dht, Lookup, LookupResponse},
};
use tokio::time::Sleep;

use crate::JoinOpts;

const REFRESH_BASE_SECS: u64 = 600; // ~10 min
const REFRESH_JITTER_SECS: u64 = 120; // up to ~2 min

enum ActiveQuery {
    Lookup(Lookup),
    Announce(Announce),
}

impl Stream for ActiveQuery {
    type Item = hyperdht::Result<Option<LookupResponse>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            ActiveQuery::Lookup(lookup) => Pin::new(lookup).poll_next(cx),
            ActiveQuery::Announce(announce) => Pin::new(announce).poll_next(cx),
        }
    }
}

enum PeerDiscoveryState {
    Querying(Box<ActiveQuery>),
    Sleeping(Pin<Box<Sleep>>),
}

pub struct PeerDiscovery {
    topic: IdBytes,
    opts: JoinOpts,
    dht: Dht,
    keypair: Keypair,
    state: PeerDiscoveryState,
    first_round_complete: bool,
    relay_addresses: Vec<SocketAddr>,
}

impl PeerDiscovery {
    pub fn new(
        topic: IdBytes,
        opts: JoinOpts,
        dht: Dht,
        keypair: Keypair,
        relay_addresses: Vec<SocketAddr>,
    ) -> Self {
        let query = Self::create_query(&dht, topic, &opts, &keypair, &relay_addresses);
        Self {
            topic,
            opts,
            dht,
            keypair,
            state: PeerDiscoveryState::Querying(query),
            first_round_complete: false,
            relay_addresses,
        }
    }

    pub fn topic(&self) -> IdBytes {
        self.topic
    }

    pub fn is_first_round_complete(&self) -> bool {
        self.first_round_complete
    }

    /// If relay addresses have changed, update them for subsequent announce queries.
    pub fn maybe_set_relay_addresses(&mut self, relay_addresses: &[SocketAddr]) {
        if self.opts.server() && relay_addresses != self.relay_addresses {
            self.relay_addresses = relay_addresses.to_vec();
        }
    }

    /// Restart the query immediately, aborting any sleep timer.
    pub fn refresh(&mut self) {
        let query = Self::create_query(
            &self.dht,
            self.topic,
            &self.opts,
            &self.keypair,
            &self.relay_addresses,
        );
        self.state = PeerDiscoveryState::Querying(query);
    }

    fn create_query(
        dht: &Dht,
        topic: IdBytes,
        opts: &JoinOpts,
        keypair: &Keypair,
        relay_addresses: &[SocketAddr],
    ) -> Box<ActiveQuery> {
        Box::new(if opts.server() {
            ActiveQuery::Announce(dht.announce(topic, keypair.clone(), relay_addresses.to_vec()))
        } else {
            ActiveQuery::Lookup(
                dht.lookup(topic, Commit::No)
                    .expect("lookup creation failed"),
            )
        })
    }

    fn refresh_duration() -> Duration {
        Duration::from_secs(REFRESH_BASE_SECS + rand::random::<u64>() % REFRESH_JITTER_SECS)
    }
}

impl Stream for PeerDiscovery {
    type Item = hyperdht::Result<Option<LookupResponse>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match &mut self.state {
                PeerDiscoveryState::Querying(query) => match Pin::new(query.as_mut()).poll_next(cx)
                {
                    Poll::Ready(Some(result)) => {
                        return Poll::Ready(Some(result));
                    }
                    Poll::Ready(None) => {
                        self.first_round_complete = true;
                        let duration = Self::refresh_duration();
                        self.state =
                            PeerDiscoveryState::Sleeping(Box::pin(tokio::time::sleep(duration)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                PeerDiscoveryState::Sleeping(timer) => match timer.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        let query = Self::create_query(
                            &self.dht,
                            self.topic,
                            &self.opts,
                            &self.keypair,
                            &self.relay_addresses,
                        );
                        self.state = PeerDiscoveryState::Querying(query);
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                },
            }
        }
    }
}
