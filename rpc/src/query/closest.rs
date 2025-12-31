// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::{
    IdBytes, Peer,
    cenc::calculate_peer_id,
    kbucket::{ALPHA_VALUE, Distance, K_VALUE, distance},
};
use std::{
    collections::btree_map::{BTreeMap, Entry},
    iter::FromIterator,
    net::SocketAddr,
    num::NonZeroUsize,
    time::Duration,
};
use tracing::{debug, instrument, trace, warn};
use wasm_timer::Instant;

use super::peers::PeersIterState;
//use web_time::Instant;

/// A peer iterator for a dynamically changing list of peers, sorted by increasing
/// distance to a chosen target.
#[derive(Debug, Clone)]
pub(crate) struct ClosestPeersIter {
    config: ClosestPeersIterConfig,

    /// The target whose distance to any peer determines the position of
    /// the peer in the iterator.
    pub target: IdBytes,

    /// The internal iterator state.
    state: State,

    /// The closest peers to the target, ordered by increasing distance.
    closest_peers: BTreeMap<Distance, IterPeer>,

    /// The number of peers for which the iterator is currently waiting for results.
    num_waiting: usize,
}

/// Configuration for a `ClosestPeersIter`.
#[derive(Debug, Clone)]
pub struct ClosestPeersIterConfig {
    /// Allowed level of parallelism.
    ///
    /// The `α` parameter in the Kademlia paper. The maximum number of peers that
    /// the iterator is allowed to wait for in parallel while iterating towards the closest
    /// nodes to a target. Defaults to `ALPHA_VALUE`.
    pub parallelism: NonZeroUsize,

    /// Number of results (closest peers) to search for.
    ///
    /// The number of closest peers for which the iterator must obtain successful results
    /// in order to finish successfully. Defaults to `K_VALUE`.
    pub num_results: NonZeroUsize,

    /// The timeout for a single peer.
    ///
    /// If a successful result is not reported for a peer within this timeout
    /// window, the iterator considers the peer unresponsive and will not wait for
    /// the peer when evaluating the termination conditions, until and unless a
    /// result is delivered. Defaults to `10` seconds.
    pub peer_timeout: Duration,
}

impl Default for ClosestPeersIterConfig {
    fn default() -> Self {
        ClosestPeersIterConfig {
            parallelism: ALPHA_VALUE,
            num_results: K_VALUE,
            peer_timeout: Duration::from_secs(10),
        }
    }
}

impl ClosestPeersIter {
    /// Creates a new iterator with a default configuration.
    #[instrument(skip_all)]
    pub fn new<I>(target: IdBytes, known_closest_peers: I) -> Self
    where
        I: IntoIterator<Item = Peer>,
    {
        Self::with_config(
            ClosestPeersIterConfig::default(),
            target,
            known_closest_peers,
        )
    }

    /// Creates a new iterator with the given configuration.
    #[instrument(skip_all)]
    pub fn with_config<I>(
        config: ClosestPeersIterConfig,
        target: IdBytes,
        known_closest_peers: I,
    ) -> Self
    where
        I: IntoIterator<Item = Peer>,
    {
        // Initialise the closest peers to start the iterator with.
        let closest_peers = BTreeMap::from_iter(
            known_closest_peers
                .into_iter()
                .map(|p| {
                    let id = calculate_peer_id(&p);
                    let distance = target.distance(id.as_slice());
                    (
                        distance,
                        IterPeer {
                            id: id.into(),
                            state: PeerState::NotContacted,
                            addr: p.addr,
                        },
                    )
                })
                .take(K_VALUE.into()),
        );
        debug!(
            n_closest_peers = closest_peers.len(),
            "ClosestPeersIter new"
        );

        // The iterator initially makes progress by iterating towards the target.
        let state = State::Iterating { no_progress: 0 };

        trace!("Creating new ClosestPeersIter");
        ClosestPeersIter {
            config,
            target,
            state,
            closest_peers,
            num_waiting: 0,
        }
    }

    /// Callback for delivering the result of a successful request to a peer.
    ///
    /// Delivering results of requests back to the iterator allows the iterator to make
    /// progress. The iterator is said to make progress either when the given
    /// `closer_peers` contain a peer closer to the target than any peer seen so far,
    /// or when the iterator did not yet accumulate `num_results` closest peers and
    /// `closer_peers` contains a new peer, regardless of its distance to the target.
    ///
    /// If the iterator is currently waiting for a result from `peer`,
    /// the iterator state is updated and `true` is returned. In that
    /// case, after calling this function, `next` should eventually be
    /// called again to obtain the new state of the iterator.
    ///
    /// If the iterator is finished, it is not currently waiting for a
    /// result from `peer`, or a result for `peer` has already been reported,
    /// calling this function has no effect and `false` is returned.
    #[instrument(skip_all)]
    pub fn on_success(
        &mut self,
        peer: &Peer,           /* peer that sent the response */
        closer_peers: &[Peer], /* closer peers sent in the response */
    ) -> bool {
        if let State::Finished = self.state {
            return false;
        }

        let id = calculate_peer_id(peer);
        let distance = distance(&id, self.target.as_ref());

        // Mark the peer as succeeded.
        match self.closest_peers.entry(distance) {
            Entry::Vacant(..) => {
                debug!(
                    "Responding Peer's distance [{:?}] is not in  self.closest_peers",
                    distance
                );
                return false;
            }
            Entry::Occupied(mut e) => match e.get().state {
                PeerState::Waiting(..) => {
                    debug_assert!(self.num_waiting > 0);
                    self.num_waiting -= 1;
                    trace!(num_waiting = self.num_waiting, "Good response from peer!");
                    e.get_mut().state = PeerState::Succeeded;
                }
                PeerState::Unresponsive => {
                    trace!("Response from unresponsive peer");
                    e.get_mut().state = PeerState::Succeeded;
                }
                state @ (PeerState::NotContacted | PeerState::Failed | PeerState::Succeeded) => {
                    warn!("Got response from Peer in strange state [{:?}]", state);
                    return false;
                }
            },
        }

        let mut cur_range = distance;
        let num_results = self.config.num_results.get();
        // furthest_peer is the furthest peer in range among the closest_peers
        let furthest_peer = self
            .closest_peers
            .iter()
            .enumerate()
            .nth(num_results - 1)
            .map(|(_, peer)| peer)
            .or_else(|| self.closest_peers.iter().last());
        if let Some((dist, _)) = furthest_peer {
            cur_range = *dist;
        }

        // Incorporate the reported closer peers into the iterator.
        //
        // The iterator makes progress if:
        //     1, the iterator did not yet accumulate enough closest peers.
        //   OR
        //     2, any of the new peers is closer to the target than any peer seen so far
        //        (i.e. is the first entry after being incorporated)
        let mut progress = self.closest_peers.len() < self.config.num_results.get();
        debug!(
            iter_progress = progress,
            n_closest_peers = closer_peers.len(),
            "incorperate peers"
        );
        for peer in closer_peers {
            let peer = IterPeer::from(peer.clone());
            let distance = peer.distance(self.target.as_ref());

            let is_first_insert = match self.closest_peers.entry(distance) {
                Entry::Occupied(_) => false,
                Entry::Vacant(entry) => {
                    entry.insert(peer);
                    true
                }
            };

            progress = (is_first_insert && distance < cur_range) || progress;
        }

        // Update the iterator state.
        self.state = match self.state {
            State::Iterating { no_progress } => {
                let no_progress = if progress { 0 } else { no_progress + 1 };
                if no_progress >= self.config.parallelism.get() {
                    State::Stalled
                } else {
                    State::Iterating { no_progress }
                }
            }
            State::Stalled => {
                if progress {
                    State::Iterating { no_progress: 0 }
                } else {
                    State::Stalled
                }
            }
            State::Finished => State::Finished,
        };

        true
    }

    /// Callback for informing the iterator about a failed request to a peer.
    ///
    /// If the iterator is currently waiting for a result from `peer`,
    /// the iterator state is updated and `true` is returned. In that
    /// case, after calling this function, `next` should eventually be
    /// called again to obtain the new state of the iterator.
    ///
    /// If the iterator is finished, it is not currently waiting for a
    /// result from `peer`, or a result for `peer` has already been reported,
    /// calling this function has no effect and `false` is returned.
    pub fn on_failure(&mut self, peer: &Peer) -> bool {
        if let State::Finished = self.state {
            return false;
        }

        let id = calculate_peer_id(peer);
        let distance = distance(&id, self.target.as_ref());

        match self.closest_peers.entry(distance) {
            Entry::Vacant(_) => return false,
            Entry::Occupied(mut e) => match e.get().state {
                PeerState::Waiting(_) => {
                    debug_assert!(self.num_waiting > 0);
                    self.num_waiting -= 1;
                    e.get_mut().state = PeerState::Failed
                }
                PeerState::Unresponsive => e.get_mut().state = PeerState::Failed,
                PeerState::NotContacted | PeerState::Failed | PeerState::Succeeded => return false,
            },
        }

        true
    }

    /// Returns the list of peers for which the iterator is currently waiting
    /// for results.
    pub fn waiting(&self) -> impl Iterator<Item = &IterPeer> {
        self.closest_peers
            .values()
            .filter(|peer| matches!(peer.state, PeerState::Waiting { .. }))
    }

    /// Returns the number of peers for which the iterator is currently
    /// waiting for results.
    #[expect(unused)] // TODO FIXME
    pub fn num_waiting(&self) -> usize {
        self.num_waiting
    }

    /// Returns true if the iterator is waiting for a response from the given peer.
    #[expect(unused)] // TODO FIXME
    pub fn is_waiting(&self, peer: &IdBytes) -> bool {
        self.waiting().any(|p| *peer == p.id)
    }

    /// Advances the state of the iterator, potentially getting a new peer to contact.
    #[instrument(skip_all)]
    pub fn next(&mut self, now: Instant) -> PeersIterState {
        if let State::Finished = self.state {
            trace!("Finished ClosestPeersIter");
            return PeersIterState::Finished;
        }

        // Count the number of peers that returned a result. If there is a
        // request in progress to one of the `num_results` closest peers, the
        // counter is set to `None` as the iterator can only finish once
        // `num_results` closest peers have responded (or there are no more
        // peers to contact, see `num_waiting`).
        let mut result_counter = Some(0);

        // Check if the iterator is at capacity w.r.t. the allowed parallelism.
        let at_capacity = self.at_capacity();

        trace!(
            "Iterating over closest N=[{}] peers",
            self.closest_peers.len()
        );
        for peer in self.closest_peers.values_mut() {
            match peer.state {
                PeerState::Waiting(timeout) => {
                    trace!(id = ?peer.id, "Peer Waing");
                    if now >= timeout {
                        // Unresponsive peers no longer count towards the limit for the
                        // bounded parallelism, though they might still be ongoing and
                        // their results can still be delivered to the iterator.
                        debug_assert!(self.num_waiting > 0);
                        self.num_waiting -= 1;
                        trace!(peer_id = ?peer.id, num_waiting = self.num_waiting, "waiting peer timed out");
                        peer.state = PeerState::Unresponsive
                    } else if at_capacity {
                        trace!(peer_id = ?peer.id, "waiting peer but iterator at capacity");

                        // The iterator is still waiting for a result from a peer and is
                        // at capacity w.r.t. the maximum number of peers being waited on.
                        return PeersIterState::WaitingAtCapacity;
                    } else {
                        trace!(peer_id = ?peer.id, "waiting peer but ...? TODO what is this block");
                        // The iterator is still waiting for a result from a peer and the
                        // `result_counter` did not yet reach `num_results`. Therefore
                        // the iterator is not yet done, regardless of already successful
                        // queries to peers farther from the target.
                        result_counter = None;
                    }
                }

                PeerState::Succeeded => {
                    if let Some(ref mut cnt) = result_counter {
                        *cnt += 1;
                        trace!(peer_id = ? peer.id, result_count = cnt, "Succeded peer. Increment result counter");
                        // If `num_results` successful results have been delivered for the
                        // closest peers, the iterator is done.
                        if *cnt >= self.config.num_results.get() {
                            trace!("Got enough results to finish iterating!!!");
                            self.state = State::Finished;
                            trace!("PeerState::Succeeded so PeersIterState::Finished");
                            return PeersIterState::Finished;
                        }
                    }
                }

                PeerState::NotContacted => {
                    if !at_capacity {
                        let timeout = now + self.config.peer_timeout;
                        peer.state = PeerState::Waiting(timeout);
                        self.num_waiting += 1;
                        trace!(peer_id = ? peer.id, num_waiting = self.num_waiting, "uncontacte peer, start wating on it");
                        //return PeersIterState::Waiting(Some(peer.key.preimage()));
                        return PeersIterState::Waiting(Some(Peer::from(peer.clone())));
                    } else {
                        trace!(peer_id = ? peer.id, "uncontacte peer, but iterator at capacity");
                        return PeersIterState::WaitingAtCapacity;
                    }
                }

                state @ (PeerState::Unresponsive | PeerState::Failed) => {
                    trace!(peer_id = ? peer.id, state = tracing::field::debug(state), "Skip this peer");
                    // Skip over unresponsive or failed peers.
                }
            }
        }

        if self.num_waiting > 0 {
            // The iterator is still waiting for results and not at capacity w.r.t.
            // the allowed parallelism, but there are no new peers to contact
            // at the moment.
            PeersIterState::Waiting(None)
        } else {
            // The iterator is finished because all available peers have been contacted
            // and the iterator is not waiting for any more results.
            self.state = State::Finished;
            trace!(
                num_waiting = self.num_waiting,
                "No more peers waiting PeersIterState::Finished"
            );
            PeersIterState::Finished
        }
    }

    /// Immediately transitions the iterator to [`PeersIterState::Finished`].
    #[expect(unused)] // TODO FIXME
    pub fn finish(&mut self) {
        self.state = State::Finished
    }

    /// Checks whether the iterator has finished.
    #[expect(unused)] // TODO FIXME
    pub fn is_finished(&self) -> bool {
        self.state == State::Finished
    }

    /// Consumes the iterator, returning the closest peers.
    #[expect(unused)] // TODO FIXME
    pub fn into_result(self) -> impl Iterator<Item = Peer> {
        self.closest_peers
            .into_iter()
            .filter_map(|(_, peer)| {
                if let PeerState::Succeeded = peer.state {
                    Some(Peer {
                        id: Some(peer.id.0),
                        addr: peer.addr,
                        referrer: None,
                    })
                } else {
                    None
                }
            })
            .take(self.config.num_results.get())
    }

    /// Checks if the iterator is at capacity w.r.t. the permitted parallelism.
    ///
    /// While the iterator is stalled, up to `num_results` parallel requests
    /// are allowed. This is a slightly more permissive variant of the
    /// requirement that the initiator "resends the FIND_NODE to all of the
    /// k closest nodes it has not already queried".
    fn at_capacity(&self) -> bool {
        match self.state {
            State::Stalled => {
                self.num_waiting
                    >= usize::max(self.config.num_results.get(), self.config.parallelism.get())
            }
            State::Iterating { .. } => self.num_waiting >= self.config.parallelism.get(),
            State::Finished => true,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Private state

/// Internal state of the iterator.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum State {
    /// The iterator is making progress by iterating towards `num_results` closest
    /// peers to the target with a maximum of `parallelism` peers for which the
    /// iterator is waiting for results at a time.
    ///
    /// > **Note**: When the iterator switches back to `Iterating` after being
    /// > `Stalled`, it may temporarily be waiting for more than `parallelism`
    /// > results from peers, with new peers only being considered once
    /// > the number pending results drops below `parallelism`.
    Iterating {
        /// The number of consecutive results that did not yield a peer closer
        /// to the target. When this number reaches `parallelism` and no new
        /// peer was discovered or at least `num_results` peers are known to
        /// the iterator, it is considered `Stalled`.
        no_progress: usize,
    },

    /// A iterator is stalled when it did not make progress after `parallelism`
    /// consecutive successful results (see `on_success`).
    ///
    /// While the iterator is stalled, the maximum allowed parallelism for pending
    /// results is increased to `num_results` in an attempt to finish the iterator.
    /// If the iterator can make progress again upon receiving the remaining
    /// results, it switches back to `Iterating`. Otherwise it will be finished.
    Stalled,

    /// The iterator is finished.
    ///
    /// A iterator finishes either when it has collected `num_results` results
    /// from the closest peers (not counting those that failed or are unresponsive)
    /// or because the iterator ran out of peers that have not yet delivered
    /// results (or failed).
    Finished,
}

/// Representation of a peer in the context of a iterator.
#[derive(Debug, Clone)]
pub(crate) struct IterPeer {
    id: IdBytes,
    state: PeerState,
    addr: SocketAddr,
}

impl From<Peer> for IterPeer {
    fn from(value: Peer) -> Self {
        Self {
            id: IdBytes::from(calculate_peer_id(&value)),
            state: PeerState::NotContacted,
            addr: value.addr,
        }
    }
}

impl From<IterPeer> for Peer {
    fn from(value: IterPeer) -> Self {
        Self {
            id: Some(value.id.0),
            addr: value.addr,
            referrer: None,
        }
    }
}

impl IterPeer {
    fn distance(&self, other: &[u8]) -> Distance {
        distance(self.id.0.as_slice(), other)
    }
}

/// The state of a single `Peer`.
#[derive(Debug, Copy, Clone)]
enum PeerState {
    /// The peer has not yet been contacted.
    ///
    /// This is the starting state for every peer.
    NotContacted,

    /// The iterator is waiting for a result from the peer.
    Waiting(Instant),

    /// A result was not delivered for the peer within the configured timeout.
    ///
    /// The peer is not taken into account for the termination conditions
    /// of the iterator until and unless it responds.
    Unresponsive,

    /// Obtaining a result from the peer has failed.
    ///
    /// This is a final state, reached as a result of a call to `on_failure`.
    Failed,

    /// A successful result from the peer has been delivered.
    ///
    /// This is a final state, reached as a result of a call to `on_success`.
    Succeeded,
}
