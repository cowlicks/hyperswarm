//! Working out our own address as the rest of the network sees it.
//!
//! A node's id is the hash of its external address ([`crate::cenc::calculate_peer_id`]),
//! and that is not something a node can read off its own socket - NAT sits in between, so
//! the address peers reply to is not necessarily the one it bound. Every message carries a
//! `to` field naming the address its sender saw us at, so a node learns its own address by
//! asking around and taking the answer the network agrees on.
//!
//! This is a port of the `nat-sampler` module JS dht-rpc uses. It keeps that module's
//! agreement rule - a candidate has to account for all but a few of the recent samples -
//! but counts the samples honestly instead of reproducing its 4-slot probe, which is an
//! optimisation detail rather than part of the behaviour. Nothing here goes on the wire.

use std::{collections::HashMap, net::SocketAddrV4};

/// Matches `nat-sampler`'s ring size.
const MAX_SAMPLES: usize = 32;

#[derive(Debug, Default)]
pub(crate) struct NatSampler {
    samples: Vec<SocketAddrV4>,
    /// Where the next sample overwrites once we are at capacity.
    next: usize,
}

impl NatSampler {
    pub(crate) fn add(&mut self, addr: SocketAddrV4) {
        if self.samples.len() < MAX_SAMPLES {
            self.samples.push(addr);
        } else {
            self.samples[self.next] = addr;
            self.next = (self.next + 1) % MAX_SAMPLES;
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.samples.len()
    }

    /// How many of the current samples a candidate has to account for. Allows a few
    /// disagreeing samples once there are enough of them to tell noise from a real change.
    fn threshold(&self) -> usize {
        let size = self.samples.len();
        let slack = match size {
            0..4 => 0,
            4..8 => 1,
            8..12 => 2,
            _ => 3,
        };
        size - slack
    }

    /// The address the samples agree on, if they agree well enough.
    ///
    /// `None` covers both "not enough agreement yet" and the symmetric-NAT case, where the
    /// host is consistent but the port is not. Either way we have no address to be the
    /// hash of, so there is no id to adopt.
    pub(crate) fn addr(&self) -> Option<SocketAddrV4> {
        if self.samples.is_empty() {
            return None;
        }

        let mut hits: HashMap<SocketAddrV4, usize> = HashMap::new();
        for sample in &self.samples {
            *hits.entry(*sample).or_default() += 1;
        }

        hits.into_iter()
            .max_by_key(|(_, hits)| *hits)
            .filter(|(_, hits)| *hits >= self.threshold())
            .map(|(addr, _)| addr)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn addr(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new([127, 0, 0, 1].into(), port)
    }

    #[test]
    fn nothing_to_report_without_samples() {
        assert_eq!(NatSampler::default().addr(), None);
    }

    #[test]
    fn one_sample_is_enough_to_go_on() {
        let mut nat = NatSampler::default();
        nat.add(addr(1234));
        assert_eq!(nat.addr(), Some(addr(1234)));
    }

    #[test]
    fn a_disagreeing_port_withholds_an_answer() {
        let mut nat = NatSampler::default();
        nat.add(addr(1));
        nat.add(addr(2));
        // Two samples, threshold 2, neither candidate accounts for both.
        assert_eq!(nat.addr(), None);
    }

    #[test]
    fn an_outlier_is_tolerated_once_there_are_enough_samples() {
        let mut nat = NatSampler::default();
        for _ in 0..7 {
            nat.add(addr(1234));
        }
        nat.add(addr(9999));
        // 8 samples, threshold 6, the agreed address accounts for 7.
        assert_eq!(nat.addr(), Some(addr(1234)));
    }

    #[test]
    fn samples_are_bounded_and_a_moved_address_eventually_wins() {
        let mut nat = NatSampler::default();
        for _ in 0..MAX_SAMPLES {
            nat.add(addr(1111));
        }
        assert_eq!(nat.len(), MAX_SAMPLES);

        for _ in 0..MAX_SAMPLES {
            nat.add(addr(2222));
        }
        assert_eq!(nat.len(), MAX_SAMPLES);
        assert_eq!(nat.addr(), Some(addr(2222)));
    }
}
