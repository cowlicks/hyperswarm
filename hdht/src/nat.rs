//! Working out what kind of NAT we are behind, from what other nodes report seeing.
//!
//! A node cannot read its external address off its own socket, so it pings a handful of DHT
//! nodes and collects the `to` address each one echoes back. The *spread* of those answers is
//! the signal: a NAT that hands out one external port whoever it is talking to produces the
//! same address every time, and one that picks a fresh port per destination produces a
//! different port from every node it asked.
//!
//! That distinction is the whole input to holepunching. It decides which of the four
//! strategies in `js/hyperdht/lib/holepuncher.js:188` a pair of peers can run, and whether
//! they can punch at all.
//!
//! Port of the classification half of `js/hyperdht/lib/nat.js`. The sampling half, which
//! chooses which nodes to ping, is I/O and lives with the code that owns a socket; this is
//! only the tally and the decision rules, so it can be tested without a network.
// `allow` rather than `expect`, because whether these read as dead depends on the build:
// under `--all-targets` the tests below use every one of them, under a plain lib build
// nothing does. Comes off when the puncher wires this in.
#![allow(dead_code)]

use std::{
    cmp::Reverse,
    net::{Ipv4Addr, SocketAddrV4},
};

use crate::cenc::Firewall;

/// How many samples we hope for before giving up on a verdict.
///
/// Four is what JS uses: enough that a random NAT shows its spread, few enough that
/// bootstrapping is not slow.
const MIN_SAMPLES: usize = 4;

/// One observed address and how many nodes reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tally<T> {
    value: T,
    hits: usize,
}

/// Records a sighting, keeping the list ordered by hits, most agreed-upon first.
///
/// The order is load bearing: every rule below reads `samples[0]` as "the winner" and
/// `samples[1]` as "the runner up".
fn add_sample<T: PartialEq>(samples: &mut Vec<Tally<T>>, value: T) {
    let Some(i) = samples.iter().position(|s| s.value == value) else {
        samples.push(Tally { value, hits: 1 });
        return;
    };
    samples[i].hits += 1;

    // `sort_by` is stable, so an address that got there first is not displaced by a latecomer
    // that merely drew level with it. That tie-break is load bearing: it is what stops the
    // reported address from flapping between two equally-attested candidates.
    samples.sort_by_key(|s| Reverse(s.hits));
}

/// The verdict so far, and the samples behind it.
#[derive(Debug)]
pub struct Nat {
    /// Whether to assume a NAT at all. A node told it is not firewalled skips the whole
    /// analysis and calls itself [`Firewall::Open`].
    firewalled: bool,
    /// Tally of external *hosts* seen. Normally one entry; more than one means something odd,
    /// such as a multi-homed connection.
    samples_host: Vec<Tally<Ipv4Addr>>,
    /// Tally of full external addresses seen. This is where the host/port spread shows up.
    samples_full: Vec<Tally<SocketAddrV4>>,
    /// Nodes already counted, so one chatty node cannot outvote the rest.
    counted: Vec<SocketAddrV4>,
    /// While frozen, samples still accumulate but the verdict does not move. A punch in
    /// flight was planned against a particular answer and must not have it change underneath.
    frozen: bool,
    firewall: Firewall,
    addresses: Vec<SocketAddrV4>,
}

impl Nat {
    /// `firewalled` is the node's own belief about whether it needs any of this, and comes
    /// from configuration rather than measurement.
    pub fn new(firewalled: bool) -> Self {
        Self {
            firewalled,
            samples_host: vec![],
            samples_full: vec![],
            counted: vec![],
            frozen: false,
            firewall: if firewalled {
                Firewall::Unknown
            } else {
                Firewall::Open
            },
            addresses: vec![],
        }
    }

    pub fn firewall(&self) -> Firewall {
        self.firewall
    }

    /// The addresses worth telling a peer to aim at.
    ///
    /// For a [`Firewall::Consistent`] node these are real host:port pairs. For a
    /// [`Firewall::Random`] one only the host is meaningful and the port is left zero, since
    /// there is no port worth reporting: that is exactly the problem such a node has.
    pub fn addresses(&self) -> &[SocketAddrV4] {
        &self.addresses
    }

    /// How many distinct nodes have reported back.
    pub fn sampled(&self) -> usize {
        self.counted.len()
    }

    /// Whether enough nodes have answered to stop asking.
    ///
    /// A predictable verdict is final the moment it is reached, because more samples can only
    /// agree. A random one is a conclusion drawn from disagreement, so it waits for the full
    /// set before anyone acts on it.
    pub fn is_settled(&self) -> bool {
        if self.firewall.is_predictable() {
            return true;
        }
        self.sampled() >= MIN_SAMPLES
    }

    /// Hold the verdict still while a punch is in flight.
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Release the verdict and take account of anything that arrived while frozen.
    pub fn unfreeze(&mut self) {
        self.frozen = false;
        self.update();
    }

    /// Record that `reporter` told us it sees us at `observed`.
    ///
    /// Only the first report from any one node counts.
    pub fn add(&mut self, observed: SocketAddrV4, reporter: SocketAddrV4) {
        if self.counted.contains(&reporter) {
            return;
        }
        self.counted.push(reporter);

        add_sample(&mut self.samples_host, *observed.ip());
        add_sample(&mut self.samples_full, observed);

        // Below three samples there is nothing to tell apart agreement from coincidence, so
        // an unfirewalled node is the only one that can conclude anything this early.
        if (self.sampled() >= 3 || !self.firewalled) && !self.frozen {
            self.update();
        }
    }

    /// Re-run the decision rules over the samples collected so far.
    pub fn update(&mut self) {
        // A node that previously called itself open, and has since been told it is
        // firewalled, has to earn a verdict like everyone else.
        if self.firewalled && self.firewall == Firewall::Open {
            self.firewall = Firewall::Unknown;
        }
        self.update_firewall();
        self.update_addresses();
    }

    /// The decision rules, from `_updateFirewall` in `js/hyperdht/lib/nat.js:96`.
    ///
    /// Everything turns on how many nodes agreed on the single most popular address. Broad
    /// agreement means one stable external port, so aiming at it works. Total disagreement
    /// means a fresh port per destination. The awkward case is exactly two agreeing, where
    /// the tie is broken by whether that agreement spans more than one host.
    fn update_firewall(&mut self) {
        if !self.firewalled {
            self.firewall = Firewall::Open;
            return;
        }

        // Too early to say anything. Leave the previous verdict alone rather than guessing.
        if self.sampled() < 3 {
            return;
        }

        let best = self.samples_full[0].hits;

        // Three nodes behind one address is agreement, and no random NAT produces it.
        if best >= 3 {
            self.firewall = Firewall::Consistent;
            return;
        }

        // Every node saw a different port. That is the definition of the problem.
        if best == 1 {
            self.firewall = Firewall::Random;
            return;
        }

        // best == 2: a pair agreed and the rest did not.

        // One host, and at least one sample disagreed with the pair. A consistent NAT would
        // not have produced that disagreement.
        if self.samples_host.len() == 1 && self.sampled() > 3 {
            self.firewall = Firewall::Random;
            return;
        }

        // Two addresses each seen twice, on different hosts. Repeating twice from two
        // vantage points is not something a per-destination port allocator does.
        if self.samples_host.len() > 1 && self.samples_full.get(1).is_some_and(|s| s.hits > 1) {
            self.firewall = Firewall::Consistent;
            return;
        }

        // All the samples we were ever going to get, and still no case for predictability.
        // Assume the worse of the two, since wrongly assuming consistency means punching at
        // an address nobody is listening on.
        if self.sampled() > MIN_SAMPLES {
            self.firewall = Firewall::Random;
        }
    }

    /// From `_updateAddresses` in `js/hyperdht/lib/nat.js:136`.
    fn update_addresses(&mut self) {
        match self.firewall {
            // Nothing worth reporting, and reporting a guess would be worse than silence.
            Firewall::Unknown => self.addresses.clear(),
            // The host is known, the port is not, and saying so is the honest answer. A peer
            // reading this learns to fire at random ports on that host rather than trusting
            // one.
            Firewall::Random => {
                self.addresses = self
                    .samples_host
                    .first()
                    .map(|s| vec![SocketAddrV4::new(s.value, 0)])
                    .unwrap_or_default();
            }
            // Everything corroborated, plus the top two regardless, so a peer still has
            // something to aim at when nothing reached two hits.
            Firewall::Consistent => {
                self.addresses = self
                    .samples_full
                    .iter()
                    .enumerate()
                    .filter(|(i, s)| s.hits >= 2 || *i < 2)
                    .map(|(_, s)| s.value)
                    .collect();
            }
            // An open node is reachable at whatever it bound, so its address does not come
            // from here. JS leaves the list untouched in this case and so do we.
            Firewall::Open => {}
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn addr(s: &str) -> SocketAddrV4 {
        s.parse().expect("test address should parse")
    }

    /// Distinct reporters, so every sample counts. Their addresses are irrelevant beyond
    /// being different from each other.
    fn reporter(n: u8) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, n), 49737)
    }

    /// Feed one observation per reporter, in order.
    fn observe(nat: &mut Nat, observed: &[&str]) {
        for (i, a) in observed.iter().enumerate() {
            nat.add(addr(a), reporter(i as u8));
        }
    }

    #[test]
    fn a_node_told_it_is_not_firewalled_never_analyses_anything() {
        let mut nat = Nat::new(false);
        assert_eq!(nat.firewall(), Firewall::Open);

        // Even samples that would otherwise read as random leave it open.
        observe(
            &mut nat,
            &["203.0.113.1:1", "203.0.113.1:2", "203.0.113.1:3"],
        );
        assert_eq!(nat.firewall(), Firewall::Open);
    }

    #[test]
    fn a_verdict_is_withheld_until_three_nodes_have_answered() {
        let mut nat = Nat::new(true);
        observe(&mut nat, &["203.0.113.1:1234", "203.0.113.1:1234"]);
        assert_eq!(
            nat.firewall(),
            Firewall::Unknown,
            "two agreeing samples are not yet evidence of anything"
        );
        assert!(nat.addresses().is_empty());

        nat.add(addr("203.0.113.1:1234"), reporter(2));
        assert_eq!(nat.firewall(), Firewall::Consistent);
    }

    #[test]
    fn three_nodes_agreeing_on_one_address_is_consistent() {
        let mut nat = Nat::new(true);
        observe(
            &mut nat,
            &["203.0.113.1:1234", "203.0.113.1:1234", "203.0.113.1:1234"],
        );
        assert_eq!(nat.firewall(), Firewall::Consistent);
        assert_eq!(nat.addresses(), [addr("203.0.113.1:1234")]);
    }

    #[test]
    fn a_different_port_from_every_node_is_random() {
        let mut nat = Nat::new(true);
        observe(
            &mut nat,
            &["203.0.113.1:1", "203.0.113.1:2", "203.0.113.1:3"],
        );
        assert_eq!(nat.firewall(), Firewall::Random);
    }

    /// The point of the whole exercise: a random NAT must not report a port, because the port
    /// it would report is the one it allocated for the node that asked, and nobody else will
    /// see it.
    #[test]
    fn a_random_nat_reports_its_host_with_no_port() {
        let mut nat = Nat::new(true);
        observe(
            &mut nat,
            &["203.0.113.1:1", "203.0.113.1:2", "203.0.113.1:3"],
        );
        assert_eq!(
            nat.addresses(),
            [SocketAddrV4::new("203.0.113.1".parse().unwrap(), 0)]
        );
    }

    /// The awkward middle: exactly two nodes agreed. On a single host, one dissenter is
    /// enough to settle it, because a consistent NAT would not have produced one.
    #[test]
    fn two_agreeing_on_one_host_with_a_dissenter_is_random() {
        let mut nat = Nat::new(true);
        observe(
            &mut nat,
            &["203.0.113.1:1234", "203.0.113.1:1234", "203.0.113.1:9999"],
        );
        assert_eq!(
            nat.firewall(),
            Firewall::Unknown,
            "three samples is not yet enough to convict on a single dissenter"
        );

        nat.add(addr("203.0.113.1:5555"), reporter(3));
        assert_eq!(nat.firewall(), Firewall::Random);
    }

    /// The other half of the middle: two addresses, each corroborated twice, on two different
    /// hosts. Repeating from two vantage points is not per-destination allocation.
    #[test]
    fn two_addresses_each_seen_twice_on_different_hosts_is_consistent() {
        let mut nat = Nat::new(true);
        observe(
            &mut nat,
            &[
                "203.0.113.1:1234",
                "203.0.113.1:1234",
                "203.0.113.2:1234",
                "203.0.113.2:1234",
            ],
        );
        assert_eq!(nat.firewall(), Firewall::Consistent);
        assert_eq!(
            nat.addresses(),
            [addr("203.0.113.1:1234"), addr("203.0.113.2:1234")],
            "both corroborated addresses are worth aiming at"
        );
    }

    /// Out of samples with no case made for predictability. Guessing consistent would send a
    /// peer punching at a port nobody is listening on, so the tie breaks the safe way.
    #[test]
    fn running_out_of_samples_undecided_falls_back_to_random() {
        let mut nat = Nat::new(true);
        observe(
            &mut nat,
            &[
                "203.0.113.1:1111",
                "203.0.113.1:1111",
                "203.0.113.2:2222",
                "203.0.113.3:3333",
                "203.0.113.4:4444",
            ],
        );
        assert_eq!(nat.firewall(), Firewall::Random);
    }

    #[test]
    fn one_node_answering_repeatedly_cannot_outvote_the_others() {
        let mut nat = Nat::new(true);
        for _ in 0..5 {
            nat.add(addr("203.0.113.1:1234"), reporter(0));
        }
        assert_eq!(
            nat.sampled(),
            1,
            "the same node should only ever count once"
        );
        assert_eq!(nat.firewall(), Firewall::Unknown);
    }

    /// A punch is planned against a particular answer, so the answer must not move while it
    /// is in flight.
    #[test]
    fn freezing_holds_the_verdict_still_but_keeps_collecting() {
        let mut nat = Nat::new(true);
        observe(
            &mut nat,
            &["203.0.113.1:1", "203.0.113.1:2", "203.0.113.1:3"],
        );
        assert_eq!(nat.firewall(), Firewall::Random);

        nat.freeze();
        for i in 3..6 {
            nat.add(addr("203.0.113.9:7000"), reporter(i));
        }
        assert_eq!(
            nat.firewall(),
            Firewall::Random,
            "a punch in flight must not have the ground move under it"
        );

        nat.unfreeze();
        assert_eq!(
            nat.firewall(),
            Firewall::Consistent,
            "but the samples were still collected and count once released"
        );
    }

    #[test]
    fn a_predictable_verdict_settles_at_once_but_a_random_one_waits() {
        let mut consistent = Nat::new(true);
        observe(
            &mut consistent,
            &["203.0.113.1:1234", "203.0.113.1:1234", "203.0.113.1:1234"],
        );
        assert!(
            consistent.is_settled(),
            "more samples can only agree, so there is nothing left to learn"
        );

        let mut random = Nat::new(true);
        observe(
            &mut random,
            &["203.0.113.1:1", "203.0.113.1:2", "203.0.113.1:3"],
        );
        assert!(
            !random.is_settled(),
            "a verdict drawn from disagreement should want the full set first"
        );

        random.add(addr("203.0.113.1:4"), reporter(3));
        assert!(random.is_settled());
    }

    #[test]
    fn the_most_agreed_address_sorts_first() {
        let mut samples = vec![];
        add_sample(&mut samples, "a");
        add_sample(&mut samples, "b");
        add_sample(&mut samples, "b");
        assert_eq!(samples[0].value, "b");

        // A latecomer drawing level does not displace the one that got there first.
        add_sample(&mut samples, "a");
        assert_eq!(samples[0].value, "b");

        add_sample(&mut samples, "a");
        assert_eq!(samples[0].value, "a");
    }
}
