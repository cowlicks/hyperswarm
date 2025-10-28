use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use async_udx::UdxStream;
use futures::{Sink, Stream};
use hypercore_protocol::sstream::sm2::{Event, Machine, MachineIo};

use crate::{cenc::NoisePayload, Error};

#[derive(Debug)]
pub struct ReadyData {
    noise_payload: NoisePayload,
    stream: UdxStream,
}

impl ReadyData {
    pub fn new(noise_payload: NoisePayload, stream: UdxStream) -> Self {
        Self {
            noise_payload,
            stream,
        }
    }
}
#[derive(Debug)]
pub enum ConnStep {
    /// Initial State
    Start,
    /// Initial hanshake message sent
    RequestSent, // is this specific initializerl
    /// Handshake Ready
    Ready(ReadyData),
    // Handshake failed
    Failed,
}

#[derive(Debug)]
pub struct ConnectionInner {
    pub handshake: Machine,
    pub udx_local_id: u32,
    pub step: ConnStep,
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub inner: Arc<RwLock<ConnectionInner>>,
}

macro_rules! w {
    ($self:expr) => {
        $self.inner.write().unwrap()
    };
}
macro_rules! r {
    ($self:expr) => {
        $self.inner.read().unwrap()
    };
}

impl Connection {
    pub fn new(handshake: Machine, udx_local_id: u32) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConnectionInner {
                handshake,
                udx_local_id,
                step: ConnStep::Start,
            })),
        }
    }
    pub fn receive_next(&self, noise: Vec<u8>) -> Result<Event, Error> {
        w!(self).handshake.receive_next(noise);
        Ok(w!(self)
            .handshake
            .next_decrypted_message()?
            .expect("recieved msg above"))
    }
    pub fn handshake_ready(&self) -> bool {
        r!(self).handshake.ready()
    }
    pub fn udx_local_id(&self) -> u32 {
        r!(self).udx_local_id
    }
    pub fn handshake_set_io(&self, io: Box<dyn MachineIo<Error = std::io::Error>>) {
        w!(self).handshake.set_io(io)
    }
    pub fn set_step(&self, step: ConnStep) {
        w!(self).step = step;
    }
    fn get_constep(&self) -> &ConnStep {
        //&r!(self).step
        todo!()
    }
}

impl Stream for Connection {
    type Item = Event;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner.write().unwrap().handshake).poll_next(cx)
    }
}
impl Sink<Vec<u8>> for Connection {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner.write().unwrap().handshake).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner.write().unwrap().handshake).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner.write().unwrap().handshake).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner.write().unwrap().handshake).poll_close(cx)
    }
}
