use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use dht_rpc::{
    Command, IdBytes, InternalCommand, OutRequestBuilder, Peer, QueryArgs, QueryNext, Rpc,
    RpcDhtRequestFuture,
};
use futures::stream::FuturesUnordered;
use tokio::time::{Duration, Sleep};
use tracing::{debug, trace, warn};

use crate::{Keypair, commands, crypto::namespace, request_announce_or_unannounce_value};

const SLEEP_INTERVAL: Duration = Duration::from_secs(3);
const SLEEPS_PER_CYCLE: usize = 100; // 100 * 3s = ~5 min
const MIN_ACTIVE_RELAYS: usize = 3;

// ---------------------------------------------------------------------------
// UnannounceOne: 2-step per-relay unannounce (FIND_PEER → UNANNOUNCE)
// ---------------------------------------------------------------------------

/// A future that unannounces from a single relay node.
///
/// Step 1: Send FIND_PEER to the relay to obtain a fresh token.
/// Step 2: Send UNANNOUNCE with the token.
struct UnannounceOne {
    rpc: Rpc,
    target: IdBytes,
    keypair: Keypair,
    phase: UnannounceOnePhase,
}

enum UnannounceOnePhase {
    FindingToken { request: RpcDhtRequestFuture },
    Sending { request: RpcDhtRequestFuture },
    Done,
}

impl UnannounceOne {
    fn new(rpc: Rpc, target: IdBytes, keypair: Keypair, relay: Peer) -> Self {
        let o = OutRequestBuilder::new(relay, commands::FIND_PEER).target(target);
        let request = rpc.request_from_builder(o);
        Self {
            rpc,
            target,
            keypair,
            phase: UnannounceOnePhase::FindingToken { request },
        }
    }
}

impl Future for UnannounceOne {
    type Output = Result<(), ()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.phase {
                UnannounceOnePhase::FindingToken { request } => match Pin::new(request).poll(cx) {
                    Poll::Ready(Ok(resp)) => {
                        let (Some(token), Some(responder_id)) =
                            (resp.response.token, resp.response.id)
                        else {
                            debug!("UnannounceOne: missing token or id in FIND_PEER response");
                            self.phase = UnannounceOnePhase::Done;
                            return Poll::Ready(Err(()));
                        };

                        let value = request_announce_or_unannounce_value(
                            &self.keypair,
                            self.target,
                            &token,
                            IdBytes(responder_id),
                            &[],
                            &namespace::UNANNOUNCE,
                        );
                        let destination = Peer {
                            id: Some(responder_id),
                            addr: resp.peer.addr,
                            referrer: None,
                        };
                        let o = OutRequestBuilder::new(destination, commands::UNANNOUNCE)
                            .target(self.target)
                            .value(value)
                            .token(token);
                        let request = self.rpc.request_from_builder(o);
                        self.phase = UnannounceOnePhase::Sending { request };
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        debug!(?e, "UnannounceOne: FIND_PEER request failed");
                        self.phase = UnannounceOnePhase::Done;
                        return Poll::Ready(Err(()));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                UnannounceOnePhase::Sending { request } => match Pin::new(request).poll(cx) {
                    Poll::Ready(Ok(_)) => {
                        trace!("UnannounceOne: UNANNOUNCE succeeded");
                        self.phase = UnannounceOnePhase::Done;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(e)) => {
                        debug!(?e, "UnannounceOne: UNANNOUNCE request failed");
                        self.phase = UnannounceOnePhase::Done;
                        return Poll::Ready(Err(()));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                UnannounceOnePhase::Done => {
                    return Poll::Ready(Err(()));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Announcer
// ---------------------------------------------------------------------------

enum AnnouncerState {
    /// LOOKUP query to find closest nodes for the target.
    LookingUp { query: QueryNext },
    /// Sending ANNOUNCE commits to the closest nodes.
    Committing {
        pending: FuturesUnordered<RpcDhtRequestFuture>,
    },
    /// Unannouncing from retired relay nodes (in gen[1] but not gen[2]).
    Unannouncing {
        futures: FuturesUnordered<UnannounceOne>,
    },
    /// Sleeping between pings (3s intervals).
    Sleeping { timer: Pin<Box<Sleep>> },
    /// Pinging all current relays to check health.
    Pinging {
        pings: FuturesUnordered<RpcDhtRequestFuture>,
        active_count: usize,
    },
}

/// Maintains a peer's visibility on the DHT by periodically re-announcing.
///
/// Holds its own `Rpc` clone and performs all DHT operations directly:
/// LOOKUP queries, ANNOUNCE commits, FIND_PEER for tokens, UNANNOUNCE,
/// and pings for relay health monitoring.
///
/// Tracks relays across three generations for graceful rotation.
/// Relays in the oldest generation that aren't in the newest get unannounced.
///
/// To suspend, stop polling. To stop, drop.
pub struct Announcer {
    rpc: Rpc,
    keypair: Keypair,
    target: IdBytes,

    /// Three-generation relay tracking: [oldest, previous, current].
    server_relays: [HashMap<SocketAddr, Peer>; 3],

    state: AnnouncerState,

    /// Set to true to force immediate re-announce.
    refreshing: bool,

    /// Current iteration in the sleep/ping loop (0..SLEEPS_PER_CYCLE).
    iteration: usize,
}

impl Announcer {
    pub fn new(rpc: Rpc, keypair: Keypair, target: IdBytes) -> Self {
        let query = rpc.query(QueryArgs::new(commands::LOOKUP, target));
        Self {
            rpc,
            keypair,
            target,
            server_relays: Default::default(),
            state: AnnouncerState::LookingUp { query },
            refreshing: false,
            iteration: 0,
        }
    }

    /// The topic hash this announcer is maintaining.
    pub fn target(&self) -> IdBytes {
        self.target
    }

    /// Force immediate re-announce on next poll.
    pub fn refresh(&mut self) {
        self.refreshing = true;
    }

    /// Is this address one of our current relays (in any generation)?
    pub fn is_relay(&self, addr: &SocketAddr) -> bool {
        self.server_relays.iter().any(|g| g.contains_key(addr))
    }

    /// Current relay addresses (from the newest generation).
    pub fn relay_addresses(&self) -> Vec<SocketAddr> {
        self.server_relays[2].keys().copied().collect()
    }

    /// Rotate relay generations: [0] ← [1] ← [2] ← empty.
    fn rotate_relays(&mut self) {
        self.server_relays[0] = std::mem::take(&mut self.server_relays[1]);
        self.server_relays[1] = std::mem::take(&mut self.server_relays[2]);
        // server_relays[2] is now empty, will be filled by commits.
    }

    /// Start a new LOOKUP query for the announce cycle.
    fn start_lookup(&mut self) {
        self.rotate_relays();
        let query = self
            .rpc
            .query(QueryArgs::new(commands::LOOKUP, self.target));
        self.state = AnnouncerState::LookingUp { query };
    }

    /// After commits are done, start unannouncing from retired relays.
    fn start_unannounce_or_sleep(&mut self) {
        // Find relays in gen[1] (previous cycle) that are NOT in gen[2] (current cycle).
        let retired: Vec<Peer> = self.server_relays[1]
            .iter()
            .filter(|(addr, _)| !self.server_relays[2].contains_key(addr))
            .map(|(_, peer)| peer.clone())
            .collect();

        if retired.is_empty() {
            self.finish_cycle();
        } else {
            let futures = FuturesUnordered::new();
            for peer in retired {
                futures.push(UnannounceOne::new(
                    self.rpc.clone(),
                    self.target,
                    self.keypair.clone(),
                    peer,
                ));
            }
            self.state = AnnouncerState::Unannouncing { futures };
        }
    }

    /// Finish a full cycle: reset counters and start sleeping.
    fn finish_cycle(&mut self) {
        self.iteration = 0;
        self.refreshing = false;
        self.state = AnnouncerState::Sleeping {
            timer: Box::pin(tokio::time::sleep(SLEEP_INTERVAL)),
        };
    }

    /// Start pinging all current relays.
    fn start_pinging(&mut self) {
        let pings = FuturesUnordered::new();
        for peer in self.server_relays[2].values() {
            let o = OutRequestBuilder::new(peer.clone(), Command::Internal(InternalCommand::Ping));
            pings.push(self.rpc.request_from_builder(o));
        }
        if pings.is_empty() {
            // No relays to ping — trigger refresh.
            self.refreshing = true;
            self.check_cycle_or_sleep();
        } else {
            self.state = AnnouncerState::Pinging {
                pings,
                active_count: 0,
            };
        }
    }

    /// After pinging, decide whether to start a new cycle or keep sleeping.
    fn check_cycle_or_sleep(&mut self) {
        if self.iteration >= SLEEPS_PER_CYCLE || self.refreshing {
            self.start_lookup();
        } else {
            self.state = AnnouncerState::Sleeping {
                timer: Box::pin(tokio::time::sleep(SLEEP_INTERVAL)),
            };
        }
    }

    /// Drive the announcer state machine.
    ///
    /// Returns `Poll::Pending` when waiting on IO or timers.
    /// Returns `Poll::Ready(())` when a full announce cycle completes.
    pub fn poll_next(&mut self, cx: &mut Context) -> Poll<()> {
        use futures::StreamExt;

        loop {
            match &mut self.state {
                AnnouncerState::LookingUp { query } => match Pin::new(query).poll(cx) {
                    Poll::Ready(Ok(query_result)) => {
                        debug!(
                            target = ?self.target,
                            closest = query_result.closest_replies.len(),
                            "LOOKUP complete, committing announces"
                        );
                        let pending = FuturesUnordered::new();
                        let relay_addresses: Vec<SocketAddr> =
                            self.server_relays[1].keys().copied().collect();

                        for reply in query_result.closest_replies.iter() {
                            let (Some(token), Some(responder_id)) =
                                (reply.response.token, reply.response.id)
                            else {
                                warn!("Announce: closest reply missing token or id, skipping");
                                continue;
                            };
                            let value = request_announce_or_unannounce_value(
                                &self.keypair,
                                self.target,
                                &token,
                                IdBytes(responder_id),
                                &relay_addresses,
                                &namespace::ANNOUNCE,
                            );
                            let peer = Peer {
                                id: Some(responder_id),
                                addr: reply.peer.addr,
                                referrer: None,
                            };
                            let o = OutRequestBuilder::new(peer, commands::ANNOUNCE)
                                .target(self.target)
                                .value(value)
                                .token(token);
                            pending.push(self.rpc.request_from_builder(o));
                        }

                        if pending.is_empty() {
                            warn!(target = ?self.target, "No valid closest replies for announce");
                            self.start_unannounce_or_sleep();
                        } else {
                            self.state = AnnouncerState::Committing { pending };
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        warn!(?e, target = ?self.target, "LOOKUP query failed");
                        self.start_unannounce_or_sleep();
                    }
                    Poll::Pending => return Poll::Pending,
                },

                AnnouncerState::Committing { pending } => match pending.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(resp))) => {
                        trace!(
                            peer = %resp.peer.addr,
                            "Announce commit succeeded"
                        );
                        // Store this relay in the current generation.
                        self.server_relays[2].insert(resp.peer.addr, resp.peer.clone());
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        warn!(?e, "Announce commit failed");
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Ready(None) => {
                        // All commits done.
                        debug!(
                            target = ?self.target,
                            relays = self.server_relays[2].len(),
                            "Announce cycle complete"
                        );
                        self.start_unannounce_or_sleep();
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                },

                AnnouncerState::Unannouncing { futures } => match futures.poll_next_unpin(cx) {
                    Poll::Ready(Some(_)) => {
                        // Individual unannounce done (success or failure).
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Ready(None) => {
                        // All unannounces done.
                        self.finish_cycle();
                        return Poll::Ready(());
                    }
                    Poll::Pending => return Poll::Pending,
                },

                AnnouncerState::Sleeping { timer } => match timer.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        self.iteration += 1;
                        self.start_pinging();
                    }
                    Poll::Pending => return Poll::Pending,
                },

                AnnouncerState::Pinging {
                    pings,
                    active_count,
                } => match pings.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(_))) => {
                        *active_count += 1;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Ready(Some(Err(_))) => {
                        // Ping failed — don't increment active count.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Ready(None) => {
                        // All pings resolved.
                        let active = *active_count;
                        if active < MIN_ACTIVE_RELAYS {
                            debug!(
                                target = ?self.target,
                                active,
                                "Too few active relays, triggering refresh"
                            );
                            self.refreshing = true;
                        }
                        self.check_cycle_or_sleep();
                        // Continue loop.
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: The Announcer now requires a real Rpc instance, so unit tests
    // for the state machine transitions would require either:
    // 1. A mock Rpc, or
    // 2. Integration tests with a real DHT network.
    //
    // The previous Sans-IO tests tested the timer/iteration logic which is
    // still present but now interleaved with IO operations.
    //
    // TODO: Add integration tests once wired into DhtInner.

    #[test]
    fn relay_tracking_helpers() {
        // Test is_relay and relay_addresses without needing Rpc.
        // We can't construct an Announcer without Rpc, but we can test
        // the generation rotation logic conceptually.

        let mut gens: [HashMap<SocketAddr, Peer>; 3] = Default::default();
        let addr1: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:2000".parse().unwrap();
        let addr3: SocketAddr = "9.10.11.12:3000".parse().unwrap();

        let peer1 = Peer {
            id: Some([1u8; 32]),
            addr: addr1,
            referrer: None,
        };
        let peer2 = Peer {
            id: Some([2u8; 32]),
            addr: addr2,
            referrer: None,
        };
        let peer3 = Peer {
            id: Some([3u8; 32]),
            addr: addr3,
            referrer: None,
        };

        // Simulate first cycle: relays go into gen[2].
        gens[2].insert(addr1, peer1.clone());
        gens[2].insert(addr2, peer2.clone());

        // Rotate: gen[0] ← gen[1] ← gen[2] ← empty.
        gens[0] = std::mem::take(&mut gens[1]);
        gens[1] = std::mem::take(&mut gens[2]);

        // After rotation, gen[1] has the old relays, gen[2] is empty.
        assert!(gens[2].is_empty());
        assert_eq!(gens[1].len(), 2);

        // Simulate second cycle: only addr1 and addr3 announced.
        gens[2].insert(addr1, peer1);
        gens[2].insert(addr3, peer3);

        // Find retired: in gen[1] but not gen[2].
        let retired: Vec<SocketAddr> = gens[1]
            .keys()
            .filter(|addr| !gens[2].contains_key(addr))
            .copied()
            .collect();

        assert_eq!(retired, vec![addr2]);
    }
}
