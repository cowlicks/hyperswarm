use futures::channel::mpsc::{self, Receiver, Sender};
/// Commit
/// * commit request - An outgoing [`ReplyMsgData`] which includes a valid token. When the message
///   is recieved and verified, the reciever does some mutation of state
use std::{collections::BTreeSet, iter::FromIterator, net::SocketAddr};

use crate::{constants::DEFAULT_COMMIT_CHANNEL_SIZE, io::Tid};

use crate::{query::QueryId, Command, IdBytes};

/// Emitted from a query's commit
#[derive(Debug)]
pub enum CommitEvent {
    // Emitted when commit process starts for Commit::Auto. Progress is Sending
    AutoStart((Sender<CommitMessage>, QueryId)),
    // emitted when commit process starts for custom. Progess is set to Sending
    CustomStart((Sender<CommitMessage>, QueryId)),
    // Emitted when commit process has rquests it wants to send. Send them.
    SendRequests((Vec<CommitMessage>, QueryId)),
    /// Commit Done
    /// TODO add info about commit, like successful replies, timeouts, etc
    Done,
}

/// Sent by user with Commit::Custom to send commit requests
#[derive(Debug)]
pub enum CommitMessage {
    /// User emit this when they want to send a commit request.
    Send(CommitRequestParams),
    /// User emits this when they've push all commit requests
    /// Casuse  Progress to transition to AwaitingReplies
    Done,
}

#[derive(Debug)]
pub struct CommitRequestParams {
    pub command: Command,
    pub target: Option<IdBytes>,
    pub value: Option<Vec<u8>>,
    pub peer: SocketAddr,
    pub query_id: QueryId,
    pub token: [u8; 32],
}

/// The kinds of [`Commit`] a [`crate::query::Query`] can have.
#[derive(Debug)]
pub enum Commit {
    No,
    Auto(Progress),
    //Custom((Option<Receiver<CommitMessages>>, Progress)),
    //Custom(Custom),
    Custom(Progress),
}

#[derive(Debug, Default)]
pub enum Progress {
    #[default]
    BeforeStart,
    /// Sending commit requests in progress. tids are added as they are sent, but also can be
    /// removed when responses are recieved
    Sending((Receiver<CommitMessage>, BTreeSet<Tid>)),
    /// awaiting replies to commit messages
    AwaitingReplies(BTreeSet<Tid>),
    Done,
}

use Progress as P;
impl Progress {
    pub fn start_sending(&mut self) -> Sender<CommitMessage> {
        if matches!(self, P::BeforeStart) {
            let (tx, rx) = mpsc::channel(DEFAULT_COMMIT_CHANNEL_SIZE);
            *self = P::Sending((rx, Default::default()));
            tx
        } else {
            panic!("Tried to start sending but already started");
        }
    }

    pub fn all_replies_recieved(&self) -> bool {
        match self {
            P::BeforeStart => false,
            P::Sending(_) => false,
            P::AwaitingReplies(tids) => tids.is_empty(),
            P::Done => true,
        }
    }
    pub fn transition_to_awaiting(&mut self) {
        *self = P::AwaitingReplies(match self {
            P::Sending((_, tids)) => tids.clone(),
            _ => panic!("not in sending"),
        })
    }

    pub fn poll(&mut self) -> Option<CommitMessage> {
        let P::Sending((rx, _tids)) = self else {
            panic!("poll while not sending");
        };
        rx.try_next().ok().flatten()
    }
    pub fn sent_tid(&mut self, tid: Tid) -> bool {
        match self {
            P::Sending((_, tids)) => tids.insert(tid),
            _ => panic!("only call while `Sending`"),
        }
        // insert to Sending.tids
    }

    pub fn start_awaiting(&mut self, tids: Vec<Tid>) {
        if matches!(self, P::BeforeStart | P::Sending(_)) {
            *self = P::AwaitingReplies(BTreeSet::from_iter(tids))
        } else {
            panic!("Tried to start commit that was already started");
        }
    }
    pub fn recieved_tid(&mut self, tid: Tid) -> bool {
        let done = match self {
            Self::AwaitingReplies(tids) => {
                tids.remove(&tid);
                tids.is_empty()
            }
            Self::Sending((_, tids)) => {
                tids.remove(&tid);
                false
            }
            _ => false,
        };
        if done {
            *self = P::Done;
        }
        matches!(self, P::Done)
    }
}
