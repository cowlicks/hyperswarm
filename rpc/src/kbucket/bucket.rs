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

//! The internal API for a single `KBucket` in a `KBucketsTable`.
//!
//! > **Note**: Uniqueness of entries w.r.t. a `Key` in a `KBucket` is not
//! > checked in this module. This is an invariant that must hold across all
//! > buckets in a `KBucketsTable` and hence is enforced by the public API
//! > of the `KBucketsTable` and in particular the public `Entry` API.

pub use crate::kbucket::K_VALUE;

use super::*;

/// A `PendingNode` is a `Node` that is pending insertion into a `KBucket`.
#[derive(Debug, Clone)]
pub struct PendingNode<TVal> {
    /// The pending node to insert.
    node: Node<IdBytes, TVal>,

    /// The status of the pending node.
    status: NodeStatus,

    /// The instant at which the pending node is eligible for insertion into a
    /// bucket.
    replace: Instant,
}

/// The status of a node in a bucket.
///
/// The status of a node in a bucket together with the time of the
/// last status change determines the position of the node in a
/// bucket.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum NodeStatus {
    /// The node is considered connected.
    Connected,
    /// The node is considered disconnected.
    Disconnected,
}

impl<TVal> PendingNode<TVal> {
    pub fn status(&self) -> NodeStatus {
        self.status
    }

    pub fn value_mut(&mut self) -> &mut TVal {
        &mut self.node.value
    }

    pub fn is_ready(&self) -> bool {
        Instant::now() >= self.replace
    }

    pub fn into_node(self) -> Node<IdBytes, TVal> {
        self.node
    }
}

/// A `Node` in a bucket, representing a peer participating
/// in the Kademlia DHT together with an associated value (e.g. contact
/// information).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node<TKey, TVal> {
    /// The key of the node, identifying the peer.
    pub key: TKey,
    /// The associated value.
    pub value: TVal,
}

/// The position of a node in a `KBucket`, i.e. a non-negative integer
/// in the range `[0, K_VALUE)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position(usize);

/// A `KBucket` is a list of up to `K_VALUE` keys and associated values,
/// ordered from least-recently connected to most-recently connected.
#[derive(Debug, Clone)]
pub struct KBucket<TVal> {
    /// The nodes contained in the bucket.
    nodes: ArrayVec<[Node<IdBytes, TVal>; K_VALUE.get()]>,

    /// The position (index) in `nodes` that marks the first connected node.
    ///
    /// Since the entries in `nodes` are ordered from least-recently connected
    /// to most-recently connected, all entries above this index are also
    /// considered connected, i.e. the range `[0, first_connected_pos)`
    /// marks the sub-list of entries that are considered disconnected and
    /// the range `[first_connected_pos, K_VALUE)` marks sub-list of entries
    /// that are considered connected.
    ///
    /// `None` indicates that there are no connected entries in the bucket, i.e.
    /// the bucket is either empty, or contains only entries for peers that are
    /// considered disconnected.
    first_connected_pos: Option<usize>,

    /// A node that is pending to be inserted into a full bucket, should the
    /// least-recently connected (and currently disconnected) node not be
    /// marked as connected within `unresponsive_timeout`.
    pending: Option<PendingNode<TVal>>,

    /// The timeout window before a new pending node is eligible for insertion,
    /// if the least-recently connected node is not updated as being connected
    /// in the meantime.
    pending_timeout: Duration,
}

/// The result of inserting an entry into a bucket.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertResult {
    /// The entry has been successfully inserted.
    Inserted,
    /// The entry is pending insertion because the relevant bucket is currently
    /// full. The entry is inserted after a timeout elapsed, if the status
    /// of the least-recently connected (and currently disconnected) node in
    /// the bucket is not updated before the timeout expires.
    Pending {
        /// The key of the least-recently connected entry that is currently
        /// considered disconnected and whose corresponding peer should
        /// be checked for connectivity in order to prevent it from
        /// being evicted. If connectivity to the peer is
        /// re-established, the corresponding entry should be updated with
        /// [`NodeStatus::Connected`].
        disconnected: IdBytes,
    },
    /// The entry was not inserted because the relevant bucket is full.
    Full,
}

/// The result of applying a pending node to a bucket, possibly
/// replacing an existing node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPending<TVal> {
    /// The key of the inserted pending node.
    pub inserted: Node<IdBytes, TVal>,
    /// The node that has been evicted from the bucket to make room for the
    /// pending node, if any.
    pub evicted: Option<Node<IdBytes, TVal>>,
}

impl<TVal> KBucket<TVal>
where
    TVal: Clone,
{
    /// Creates a new `KBucket` with the given timeout for pending entries.
    pub fn new(pending_timeout: Duration) -> Self {
        KBucket {
            nodes: ArrayVec::new(),
            first_connected_pos: None,
            pending: None,
            pending_timeout,
        }
    }

    /// Returns a reference to the pending node of the bucket, if there is any.
    pub fn pending(&self) -> Option<&PendingNode<TVal>> {
        self.pending.as_ref()
    }

    /// Returns a mutable reference to the pending node of the bucket, if there
    /// is any.
    pub fn pending_mut(&mut self) -> Option<&mut PendingNode<TVal>> {
        self.pending.as_mut()
    }

    /// Returns a reference to the pending node of the bucket, if there is any
    /// with a matching key.
    pub fn as_pending(&self, key: &IdBytes) -> Option<&PendingNode<TVal>> {
        self.pending()
            .filter(|p| p.node.key.as_ref() == key.as_ref())
    }

    /// Returns a reference to a node in the bucket.
    #[allow(unused)] // TODO FIXME
    pub fn get(&self, key: &IdBytes) -> Option<&Node<IdBytes, TVal>> {
        self.position(key).map(|p| &self.nodes[p.0])
    }

    /// Returns an iterator over the nodes in the bucket, together with their
    /// status.
    pub fn iter(&self) -> impl Iterator<Item = (&Node<IdBytes, TVal>, NodeStatus)> {
        self.nodes
            .iter()
            .enumerate()
            .map(move |(p, n)| (n, self.status(Position(p))))
    }

    /// Inserts the pending node into the bucket, if its timeout has elapsed,
    /// replacing the least-recently connected node.
    ///
    /// If a pending node has been inserted, its key is returned together with
    /// the node that was replaced. `None` indicates that the nodes in the
    /// bucket remained unchanged.
    pub fn apply_pending(&mut self) -> Option<AppliedPending<TVal>> {
        if let Some(pending) = self.pending.take() {
            if pending.replace <= Instant::now() {
                if self.nodes.is_full() {
                    if self.status(Position(0)) == NodeStatus::Connected {
                        // The bucket is full with connected nodes. Drop the pending node.
                        return None;
                    }
                    debug_assert!(self.first_connected_pos.map_or(true, |p| p > 0)); // (*)
                                                                                     // The pending node will be inserted.
                    let inserted = pending.node.clone();
                    // A connected pending node goes at the end of the list for
                    // the connected peers, removing the least-recently connected.
                    if pending.status == NodeStatus::Connected {
                        let evicted = Some(self.nodes.remove(0));
                        self.first_connected_pos = self
                            .first_connected_pos
                            .map_or_else(|| Some(self.nodes.len()), |p| p.checked_sub(1));
                        self.nodes.push(pending.node);
                        return Some(AppliedPending { inserted, evicted });
                    }
                    // A disconnected pending node goes at the end of the list
                    // for the disconnected peers.
                    else if let Some(p) = self.first_connected_pos {
                        let insert_pos = p.checked_sub(1).expect("by (*)");
                        let evicted = Some(self.nodes.remove(0));
                        self.nodes.insert(insert_pos, pending.node);
                        return Some(AppliedPending { inserted, evicted });
                    } else {
                        // All nodes are disconnected. Insert the new node as the most
                        // recently disconnected, removing the least-recently disconnected.
                        let evicted = Some(self.nodes.remove(0));
                        self.nodes.push(pending.node);
                        return Some(AppliedPending { inserted, evicted });
                    }
                } else {
                    // There is room in the bucket, so just insert the pending node.
                    let inserted = pending.node.clone();
                    match self.insert(pending.node, pending.status) {
                        InsertResult::Inserted => {
                            return Some(AppliedPending {
                                inserted,
                                evicted: None,
                            })
                        }
                        _ => unreachable!("Bucket is not full."),
                    }
                }
            } else {
                self.pending = Some(pending);
            }
        }

        None
    }

    /// Updates the status of the pending node, if any.
    pub fn update_pending(&mut self, status: NodeStatus) {
        if let Some(pending) = &mut self.pending {
            pending.status = status
        }
    }

    /// Removes the pending node from the bucket, if any.
    pub fn remove_pending(&mut self) -> Option<PendingNode<TVal>> {
        self.pending.take()
    }

    /// Updates the status of the node referred to by the given key, if it is
    /// in the bucket.
    pub fn update(&mut self, key: &IdBytes, status: NodeStatus) {
        // Remove the node from its current position and then reinsert it
        // with the desired status, which puts it at the end of either the
        // prefix list of disconnected nodes or the suffix list of connected
        // nodes (i.e. most-recently disconnected or most-recently connected,
        // respectively).
        if let Some((node, _status, pos)) = self.remove(key) {
            // If the least-recently connected node re-establishes its
            // connected status, drop the pending node.
            if pos == Position(0) && status == NodeStatus::Connected {
                self.pending = None
            }
            // Reinsert the node with the desired status.
            match self.insert(node, status) {
                InsertResult::Inserted => {}
                _ => unreachable!("The node is removed before being (re)inserted."),
            }
        }
    }

    /// Inserts a new node into the bucket with the given status.
    ///
    /// The status of the node to insert determines the result as follows:
    ///
    ///   * `NodeStatus::Connected`: If the bucket is full and either all nodes
    ///     are connected or there is already a pending node, insertion fails
    ///     with `InsertResult::Full`. If the bucket is full but at least one
    ///     node is disconnected and there is no pending node, the new node is
    ///     inserted as pending, yielding `InsertResult::Pending`. Otherwise the
    ///     bucket has free slots and the new node is added to the end of the
    ///     bucket as the most-recently connected node.
    ///
    ///   * `NodeStatus::Disconnected`: If the bucket is full, insertion fails
    ///     with `InsertResult::Full`. Otherwise the bucket has free slots and
    ///     the new node is inserted at the position preceding the first
    ///     connected node, i.e. as the most-recently disconnected node. If
    ///     there are no connected nodes, the new node is added as the last
    ///     element of the bucket.
    pub fn insert(&mut self, node: Node<IdBytes, TVal>, status: NodeStatus) -> InsertResult {
        match status {
            NodeStatus::Connected => {
                if self.nodes.is_full() {
                    if self.first_connected_pos == Some(0) || self.pending.is_some() {
                        return InsertResult::Full;
                    } else {
                        self.pending = Some(PendingNode {
                            node,
                            status: NodeStatus::Connected,
                            replace: Instant::now() + self.pending_timeout,
                        });
                        return InsertResult::Pending {
                            disconnected: self.nodes[0].key,
                        };
                    }
                }
                let pos = self.nodes.len();
                self.first_connected_pos = self.first_connected_pos.or(Some(pos));
                self.nodes.push(node);
                InsertResult::Inserted
            }
            NodeStatus::Disconnected => {
                if self.nodes.is_full() {
                    return InsertResult::Full;
                }
                if let Some(ref mut p) = self.first_connected_pos {
                    self.nodes.insert(*p, node);
                    *p += 1;
                } else {
                    self.nodes.push(node);
                }
                InsertResult::Inserted
            }
        }
    }

    /// Removes the node with the given key from the bucket, if it exists.
    pub fn remove(&mut self, key: &IdBytes) -> Option<(Node<IdBytes, TVal>, NodeStatus, Position)> {
        if let Some(pos) = self.position(key) {
            // Remove the node from its current position.
            let status = self.status(pos);
            let node = self.nodes.remove(pos.0);
            // Adjust `first_connected_pos` accordingly.
            match status {
                NodeStatus::Connected => {
                    if self.first_connected_pos.map_or(false, |p| p == pos.0)
                        && pos.0 == self.nodes.len()
                    {
                        // It was the last connected node.
                        self.first_connected_pos = None
                    }
                }
                NodeStatus::Disconnected => {
                    if let Some(ref mut p) = self.first_connected_pos {
                        *p -= 1;
                    }
                }
            }
            Some((node, status, pos))
        } else {
            None
        }
    }

    /// Returns the status of the node at the given position.
    pub fn status(&self, pos: Position) -> NodeStatus {
        if self.first_connected_pos.map_or(false, |i| pos.0 >= i) {
            NodeStatus::Connected
        } else {
            NodeStatus::Disconnected
        }
    }

    /// Checks whether the given position refers to a connected node.
    #[allow(unused)] // TODO FIXME
    pub fn is_connected(&self, pos: Position) -> bool {
        self.status(pos) == NodeStatus::Connected
    }

    /// Gets the number of entries currently in the bucket.
    pub fn num_entries(&self) -> usize {
        self.nodes.len()
    }

    /// Gets the number of entries in the bucket that are considered connected.
    #[allow(unused)] // TODO FIXME
    pub fn num_connected(&self) -> usize {
        self.first_connected_pos.map_or(0, |i| self.nodes.len() - i)
    }

    /// Gets the number of entries in the bucket that are considered
    /// disconnected.
    #[allow(unused)] // TODO FIXME
    pub fn num_disconnected(&self) -> usize {
        self.nodes.len() - self.num_connected()
    }

    /// Gets the position of an node in the bucket.
    pub fn position(&self, key: &IdBytes) -> Option<Position> {
        self.nodes
            .iter()
            .position(|p| p.key.as_ref() == key.as_ref())
            .map(Position)
    }

    /// Gets a mutable reference to the node identified by the given key.
    ///
    /// Returns `None` if the given key does not refer to a node in the
    /// bucket.
    pub fn get_mut(&mut self, key: &IdBytes) -> Option<&mut Node<IdBytes, TVal>> {
        self.nodes
            .iter_mut()
            .find(move |p| p.key.as_ref() == key.as_ref())
    }
}
