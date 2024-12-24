#![allow(unused)]
use futures::channel::mpsc::{self, Receiver, Sender};
/// Commit
/// * commit request - An outgoing [`ReplyMsgData`] which includes a valid token. When the message
/// is recieved and verified, the reciever does some mutation of state
use std::{
    collections::{BTreeMap, BTreeSet},
    iter::FromIterator,
    net::SocketAddr,
};

use crate::{constants::DEFAULT_COMMIT_CHANNEL_SIZE, io::Tid};

use crate::{query::QueryId, Command, IdBytes};

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

#[derive(Debug)]
pub enum Commit {
    No,
    Auto(Progress),
    //Custom((Option<Receiver<CommitMessages>>, Progress)),
    //Custom(Custom),
    Custom(Progress),
}

impl Default for Progress {
    fn default() -> Self {
        Self::BeforeStart
    }
}
#[derive(Debug)]
pub enum Progress {
    BeforeStart,
    /// Sending commit requests in progress. tids are added as they are sent, but also can be
    /// removed when responses are recieved
    Sending((Receiver<CommitMessage>, BTreeSet<Tid>)),
    /// awaiting replies to commit messages
    AwaitingReplies(BTreeSet<Tid>),
    Done,
}

use Progress::*;
impl Progress {
    pub fn start_sending(&mut self) -> Sender<CommitMessage> {
        if matches!(self, BeforeStart) {
            let (tx, rx) = mpsc::channel(DEFAULT_COMMIT_CHANNEL_SIZE);
            *self = Sending((rx, Default::default()));
            tx
        } else {
            panic!("Tried to start sending but already started");
        }
    }

    pub fn all_replies_recieved(&self) -> bool {
        match self {
            BeforeStart => false,
            Sending(_) => false,
            AwaitingReplies(tids) => tids.is_empty(),
            Done => true,
        }
    }
    pub fn transition_to_awaiting(&mut self) {
        *self = AwaitingReplies(match self {
            Sending((_, tids)) => tids.clone(),
            _ => panic!("not in sending"),
        })
    }

    pub fn poll(&mut self) -> Option<CommitMessage> {
        let Sending((rx, _tids)) = self else {
            panic!("poll while not sending");
        };
        rx.try_next().ok().flatten()
    }
    pub fn sent_tid(&mut self, tid: Tid) -> bool {
        match self {
            Sending((rx, tids)) => tids.insert(tid),
            _ => panic!("only call while `Sending`"),
        }
        // insert to Sending.tids
    }

    pub fn start_awaiting(&mut self, tids: Vec<Tid>) {
        if matches!(self, BeforeStart | Sending(_)) {
            *self = AwaitingReplies(BTreeSet::from_iter(tids))
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
            *self = Done;
        }
        matches!(self, Done)
    }
}
