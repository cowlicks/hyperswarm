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

//! The `Entry` API for quering and modifying the entries of a `KBucketsTable`
//! representing the nodes participating in the Kademlia DHT.

use super::*;
pub use super::{
    bucket::{AppliedPending, InsertResult, Node, NodeStatus},
    key::*,
};

/// An immutable by-reference view of a bucket entry.
#[derive(Debug)]
pub struct EntryRefView<'a, TVal> {
    /// The node represented by the entry.
    pub node: NodeRefView<'a, TVal>,
    /// The status of the node identified by the key.
    pub status: NodeStatus,
}

/// An immutable by-reference view of a `Node`.
#[derive(Debug)]
pub struct NodeRefView<'a, TVal> {
    pub key: &'a IdBytes,
    pub value: &'a TVal,
}

impl<TVal> EntryRefView<'_, TVal> {
    pub fn to_owned(&self) -> EntryView<TVal>
    where
        TVal: Clone,
    {
        EntryView {
            node: Node {
                key: *self.node.key,
                value: self.node.value.clone(),
            },
            status: self.status,
        }
    }
}

/// A cloned, immutable view of an entry that is either present in a bucket
/// or pending insertion.
#[derive(Clone, Debug)]
pub struct EntryView<TVal> {
    /// The node represented by the entry.
    pub node: Node<IdBytes, TVal>,
    /// The status of the node.
    pub status: NodeStatus,
}

impl<TVal> AsRef<IdBytes> for EntryView<TVal> {
    fn as_ref(&self) -> &IdBytes {
        &self.node.key
    }
}

/// A reference into a single entry of a `KBucketsTable`.
#[derive(Debug)]
pub enum Entry<'a, TVal> {
    /// The entry is present in a bucket.
    Present(PresentEntry<'a, TVal>, NodeStatus),
    /// The entry is pending insertion in a bucket.
    Pending(PendingEntry<'a, TVal>, NodeStatus),
    /// The entry is absent and may be inserted.
    Absent(AbsentEntry<'a, TVal>),
    /// The entry represents the local node.
    #[expect(clippy::enum_variant_names)]
    SelfEntry,
}

/// The internal representation of the different states of an `Entry`,
/// referencing the associated key and bucket.
#[derive(Debug)]
struct EntryRef<'a, TVal> {
    bucket: &'a mut KBucket<TVal>,
    key: &'a IdBytes,
}

impl<'a, TVal> Entry<'a, TVal>
where
    TVal: Clone,
{
    /// Creates a new `Entry` for a `Key`, encapsulating access to a bucket.
    pub(super) fn new(bucket: &'a mut KBucket<TVal>, key: &'a IdBytes) -> Self {
        if let Some(pos) = bucket.position(key) {
            let status = bucket.status(pos);
            Entry::Present(PresentEntry::new(bucket, key), status)
        } else if let Some(pending) = bucket.as_pending(key) {
            let status = pending.status();
            Entry::Pending(PendingEntry::new(bucket, key), status)
        } else {
            Entry::Absent(AbsentEntry::new(bucket, key))
        }
    }

    /// Creates an immutable by-reference view of the entry.
    ///
    /// Returns `None` if the entry is neither present in a bucket nor
    /// pending insertion into a bucket.
    pub fn view(&'a mut self) -> Option<EntryRefView<'a, TVal>> {
        match self {
            Entry::Present(entry, status) => Some(EntryRefView {
                node: NodeRefView {
                    key: entry.0.key,
                    value: entry.value(),
                },
                status: *status,
            }),
            Entry::Pending(entry, status) => Some(EntryRefView {
                node: NodeRefView {
                    key: entry.0.key,
                    value: entry.value(),
                },
                status: *status,
            }),
            _ => None,
        }
    }

    /// Returns the key of the entry.
    ///
    /// Returns `None` if the `Key` used to construct this `Entry` is not a
    /// valid key for an entry in a bucket, which is the case for the
    /// `local_key` of the `KBucketsTable` referring to the local node.
    pub fn key(&self) -> Option<&IdBytes> {
        match self {
            Entry::Present(entry, _) => Some(entry.key()),
            Entry::Pending(entry, _) => Some(entry.key()),
            Entry::Absent(entry) => Some(entry.key()),
            Entry::SelfEntry => None,
        }
    }

    /// Returns the value associated with the entry.
    ///
    /// Returns `None` if the entry is absent from any bucket or refers to the
    /// local node.
    pub fn value(&mut self) -> Option<&mut TVal> {
        match self {
            Entry::Present(entry, _) => Some(entry.value()),
            Entry::Pending(entry, _) => Some(entry.value()),
            Entry::Absent(_) => None,
            Entry::SelfEntry => None,
        }
    }
}

/// An entry present in a bucket.
#[derive(Debug)]
pub struct PresentEntry<'a, TVal>(EntryRef<'a, TVal>);

impl<'a, TVal> PresentEntry<'a, TVal>
where
    TVal: Clone,
{
    fn new(bucket: &'a mut KBucket<TVal>, key: &'a IdBytes) -> Self {
        PresentEntry(EntryRef { bucket, key })
    }

    /// Returns the key of the entry.
    pub fn key(&self) -> &IdBytes {
        self.0.key
    }

    /// Returns the value associated with the key.
    pub fn value(&mut self) -> &mut TVal {
        &mut self
            .0
            .bucket
            .get_mut(self.0.key)
            .expect("We can only build a PresentEntry if the entry is in the bucket; QED")
            .value
    }

    /// Sets the status of the entry to `NodeStatus::Disconnected`.
    pub fn update(self, status: NodeStatus) -> Self {
        self.0.bucket.update(self.0.key, status);
        Self::new(self.0.bucket, self.0.key)
    }

    /// Removes the entry from the bucket.
    pub fn remove(self) -> EntryView<TVal> {
        let (node, status, _pos) = self
            .0
            .bucket
            .remove(self.0.key)
            .expect("We can only build a PresentEntry if the entry is in the bucket; QED");
        EntryView { node, status }
    }
}

/// An entry waiting for a slot to be available in a bucket.
#[derive(Debug)]
pub struct PendingEntry<'a, TVal>(EntryRef<'a, TVal>);

impl<'a, TVal> PendingEntry<'a, TVal>
where
    TVal: Clone,
{
    fn new(bucket: &'a mut KBucket<TVal>, key: &'a IdBytes) -> Self {
        PendingEntry(EntryRef { bucket, key })
    }

    /// Returns the key of the entry.
    pub fn key(&self) -> &IdBytes {
        self.0.key
    }

    /// Returns the value associated with the key.
    pub fn value(&mut self) -> &mut TVal {
        self.0
            .bucket
            .pending_mut()
            .expect("We can only build a ConnectedPendingEntry if the entry is pending; QED")
            .value_mut()
    }

    /// Updates the status of the pending entry.
    pub fn update(self, status: NodeStatus) -> PendingEntry<'a, TVal> {
        self.0.bucket.update_pending(status);
        PendingEntry::new(self.0.bucket, self.0.key)
    }

    /// Removes the pending entry from the bucket.
    pub fn remove(self) -> EntryView<TVal> {
        let pending = self.0.bucket.remove_pending().expect(
            "We can only build a PendingEntry if the entry is pending insertion
                    into the bucket; QED",
        );
        let status = pending.status();
        let node = pending.into_node();
        EntryView { node, status }
    }
}

/// An entry that is not present in any bucket.
#[derive(Debug)]
pub struct AbsentEntry<'a, TVal>(EntryRef<'a, TVal>);

impl<'a, TVal> AbsentEntry<'a, TVal>
where
    TVal: Clone,
{
    fn new(bucket: &'a mut KBucket<TVal>, key: &'a IdBytes) -> Self {
        AbsentEntry(EntryRef { bucket, key })
    }

    /// Returns the key of the entry.
    pub fn key(&self) -> &IdBytes {
        self.0.key
    }

    /// Attempts to insert the entry into a bucket.
    pub fn insert(self, value: TVal, status: NodeStatus) -> InsertResult {
        self.0.bucket.insert(
            Node {
                key: *self.0.key,
                value,
            },
            status,
        )
    }
}
