use std::{
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use compact_encoding::{
    CompactEncoding, EncodingError, VecEncodable, decode_usize, encode_usize_var,
    encoded_size_usize, map_decode, take_array, vec_encoded_size_for_fixed_sized_elements,
    write_array,
};

use crate::{
    Command, Error, ExternalCommand, IdBytes, InternalCommand, Peer, Result,
    constants::{HASH_SIZE, ID_SIZE, REQUEST_ID, RESPONSE_ID},
    message::{MsgData, ReplyMsgData, RequestMsgData},
};

impl CompactEncoding for InternalCommand {
    fn encoded_size(&self) -> std::result::Result<usize, EncodingError> {
        Ok(1)
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> std::result::Result<&'a mut [u8], EncodingError> {
        write_array(&[*self as u8], buffer)
    }

    fn decode(buffer: &[u8]) -> std::result::Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ([value], rest) = take_array::<1>(buffer)?;
        let cmd = InternalCommand::try_from(value).map_err(EncodingError::from)?;
        Ok((cmd, rest))
    }
}

impl From<Error> for EncodingError {
    fn from(value: Error) -> Self {
        EncodingError {
            kind: compact_encoding::EncodingErrorKind::InvalidData,
            message: value.to_string(),
        }
    }
}

impl CompactEncoding for Peer {
    fn encoded_size(&self) -> std::result::Result<usize, EncodingError> {
        Ok(6)
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> std::result::Result<&'a mut [u8], EncodingError> {
        let rest = if let IpAddr::V4(ip) = self.addr.ip() {
            ip.encode(buffer)?
        } else {
            panic!("Peer's only support ipv4")
        };
        self.addr.port().encode(rest)
    }

    fn decode(buffer: &[u8]) -> std::result::Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((ip, port), rest) = map_decode!(buffer, [Ipv4Addr, u16]);
        Ok((
            Peer {
                id: None,
                addr: SocketAddr::from((ip, port)),
                referrer: None,
            },
            rest,
        ))
    }
}

impl VecEncodable for Peer {
    fn vec_encoded_size(vec: &[Self]) -> std::result::Result<usize, EncodingError>
    where
        Self: Sized,
    {
        Ok(vec_encoded_size_for_fixed_sized_elements(
            vec,
            Peer::ENCODED_SIZE,
        ))
    }
}

pub fn ipv4(addr: &SocketAddr) -> Result<Ipv4Addr> {
    if let IpAddr::V4(ip) = addr.ip() {
        return Ok(ip);
    }
    Err(crate::Error::Ipv6NotSupported)
}

const IP_AND_PORT_NUM_BYTES: usize = 6;

/// TODO this will panic for ipv6
fn id_from_socket(addr: &SocketAddr) -> [u8; ID_SIZE] {
    let mut from_buff = vec![0; IP_AND_PORT_NUM_BYTES];
    let rest = if let IpAddr::V4(ip) = addr.ip() {
        ip.encode(&mut from_buff).expect("TODO")
    } else {
        panic!("We only support ipv4")
    };

    let _ = addr.port().encode(rest).expect("TODO");
    generic_hash(&from_buff)
}

pub(crate) fn calculate_peer_id(from: &Peer) -> [u8; ID_SIZE] {
    id_from_socket(&from.addr)
}

pub fn generic_hash(input: &[u8]) -> [u8; HASH_SIZE] {
    let mut out = [0; HASH_SIZE];
    let ret = unsafe {
        libsodium_sys::crypto_generichash(
            out.as_mut_ptr(),
            out.len(),
            input.as_ptr(),
            input.len() as u64,
            std::ptr::null(),
            0,
        )
    };
    if ret != 0 {
        panic!("Only errors when the input is invalid. Inputs here or checked");
    }
    out
}

pub(crate) fn generic_hash_with_key(input: &[u8], key: &[u8]) -> Result<[u8; HASH_SIZE]> {
    let mut out = [0; HASH_SIZE];
    let ret = unsafe {
        libsodium_sys::crypto_generichash(
            out.as_mut_ptr(),
            out.len(),
            input.as_ptr(),
            input.len() as u64,
            key.as_ptr(),
            key.len(),
        )
    };
    if ret != 0 {
        return Err(Error::LibSodiumGenericHashError(ret));
    }
    Ok(out)
}

pub(crate) fn validate_id(id: &Option<[u8; ID_SIZE]>, from: &Peer) -> Option<IdBytes> {
    if let Some(id) = id {
        if id == &calculate_peer_id(from) {
            return Some(IdBytes::from(*id));
        }
    }
    None
}

macro_rules! maybe_add_flag {
    ($cond:expr, $shift:expr) => {
        if $cond { 1 << $shift } else { 0 }
    };
}

macro_rules! maybe_decode {
    ($type:ty, $cond:expr, $buf:expr) => {
        if $cond {
            let (out, rest) = <$type>::decode($buf)?;
            (Some(out), rest)
        } else {
            (None, $buf)
        }
    };
}

impl CompactEncoding for RequestMsgData {
    fn encoded_size(&self) -> std::result::Result<usize, EncodingError> {
        let mut out = 1 + // REQUEST_ID
                      1 + // flags
                      2 + // tid
                      6 + // peer
                      1   // command byte
                    ;
        if self.id.is_some() {
            out += ID_SIZE;
        }
        if self.token.is_some() {
            out += 32;
        }
        if self.target.is_some() {
            out += 32;
        }
        if let Some(v) = &self.value {
            out += v.encoded_size()?;
        }
        Ok(out)
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> std::result::Result<&'a mut [u8], EncodingError> {
        let mut flags: u8 = 0;
        let is_internal = matches!(self.command, Command::Internal(_));
        flags |= maybe_add_flag!(self.id.is_some(), 0);
        flags |= maybe_add_flag!(self.token.is_some(), 1);
        flags |= maybe_add_flag!(is_internal, 2);
        flags |= maybe_add_flag!(self.target.is_some(), 3);
        flags |= maybe_add_flag!(self.value.is_some(), 4);

        let mut rest = write_array(&[REQUEST_ID, flags], buffer)?;
        rest = self.tid.encode(rest)?;
        rest = CompactEncoding::encode(&self.to, rest)?;
        if let Some(id) = &self.id {
            rest = id.encode(rest)?;
        }
        if let Some(token) = &self.token {
            rest = token.encode(rest)?;
        }
        rest = u8::encode(&self.command.encode(), rest)?;
        if let Some(target) = &self.target {
            rest = target.encode(rest)?;
        }
        if let Some(v) = &self.value {
            rest = v.encode(rest)?
        }
        //println!(
        //    "
        //MSGENCODE
        //etid = {}
        //einternal = {}
        //ecommand = {}
        //",
        //    self.tid, is_internal, self.command
        //);
        Ok(rest)
    }

    fn decode(buffer: &[u8]) -> std::result::Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let (([_req_flag, flags], tid, to), rest) = map_decode!(buffer, [[u8; 2], u16, Peer]);
        // assert_eq!(_req_flag, REQUEST_ID)
        let (id, rest) = maybe_decode!([u8; 32], flags & (1 << 0) != 0, rest);
        let (token, rest) = maybe_decode!([u8; 32], flags & (1 << 1) != 0, rest);
        let internal = (flags & 1 << 2) != 0;
        let ([cmd_u8], rest) = take_array::<1>(rest)?;
        let command = if internal {
            Command::from(InternalCommand::try_from(cmd_u8).map_err(EncodingError::from)?)
        } else {
            Command::from(ExternalCommand(cmd_u8 as usize))
        };
        let (target, rest) = maybe_decode!([u8; 32], flags & (1 << 3) != 0, rest);
        let (value, rest) = maybe_decode!(Vec<u8>, flags & (1 << 4) != 0, rest);
        Ok((
            Self {
                tid,
                to,
                id,
                token,
                command,
                target,
                value,
            },
            rest,
        ))
    }
}

impl CompactEncoding for ReplyMsgData {
    fn encoded_size(&self) -> std::result::Result<usize, EncodingError> {
        let mut out: usize = 1 + // RESPONSE_ID
                             1 + // flags
                             6 + // to
                             2   // tid
                            ;
        if self.id.is_some() {
            out += 32;
        }
        if self.token.is_some() {
            out += 32;
        }
        if !self.closer_nodes.is_empty() {
            out += self.closer_nodes.encoded_size()?;
        }
        if self.error > 0 {
            out += encoded_size_usize(self.error);
        }
        if let Some(v) = &self.value {
            out += v.encoded_size()?;
        }

        Ok(out)
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> std::result::Result<&'a mut [u8], EncodingError> {
        let mut flags: u8 = 0;
        flags |= maybe_add_flag!(self.id.is_some(), 0);
        flags |= maybe_add_flag!(self.token.is_some(), 1);
        flags |= maybe_add_flag!(!self.closer_nodes.is_empty(), 2);
        flags |= maybe_add_flag!(self.error > 0, 3);
        flags |= maybe_add_flag!(self.value.is_some(), 4);

        let mut rest = write_array(&[RESPONSE_ID, flags], buffer)?;
        rest = self.tid.encode(rest)?;
        rest = CompactEncoding::encode(&self.to, rest)?;
        if let Some(id) = &self.id {
            rest = id.encode(rest)?;
        }
        if let Some(token) = &self.token {
            rest = token.encode(rest)?;
        }
        if !self.closer_nodes.is_empty() {
            rest = self.closer_nodes.encode(rest)?;
        }
        if self.error > 0 {
            rest = encode_usize_var(&self.error, rest)?;
        }
        if let Some(v) = &self.value {
            rest = v.encode(rest)?
        }
        Ok(rest)
    }

    fn decode(buffer: &[u8]) -> std::result::Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let (([_, flags], tid, to), rest) = map_decode!(buffer, [[u8; 2], u16, Peer]);
        let (id, rest) = maybe_decode!([u8; 32], flags & (1 << 0) != 0, rest);
        let (token, rest) = maybe_decode!([u8; 32], flags & (1 << 1) != 0, rest);
        let (closer_nodes, rest) = if flags & (1 << 2) != 0 {
            <Vec<Peer> as CompactEncoding>::decode(rest)?
        } else {
            (vec![], rest)
        };
        let (error, rest) = if flags & (1 << 3) != 0 {
            decode_usize(rest)?
        } else {
            (0, rest)
        };
        let (value, rest) = maybe_decode!(Vec<u8>, flags & (1 << 4) != 0, rest);
        Ok((
            Self {
                tid,
                to,
                id,
                token,
                closer_nodes,
                error,
                value,
            },
            rest,
        ))
    }
}

impl CompactEncoding for MsgData {
    fn encoded_size(&self) -> std::result::Result<usize, EncodingError> {
        match self {
            MsgData::Request(x) => x.encoded_size(),
            MsgData::Reply(x) => x.encoded_size(),
        }
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> std::result::Result<&'a mut [u8], EncodingError> {
        match self {
            MsgData::Request(x) => x.encode(buffer),
            MsgData::Reply(x) => x.encode(buffer),
        }
    }

    fn decode(buffer: &[u8]) -> std::result::Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let req_resp_flag = buffer[0];
        Ok(match req_resp_flag {
            REQUEST_ID => {
                let (msg, rest) = RequestMsgData::decode(buffer)?;
                (MsgData::Request(msg), rest)
            }
            RESPONSE_ID => {
                let (msg, rest) = ReplyMsgData::decode(buffer)?;
                (MsgData::Reply(msg), rest)
            }
            _ => {
                return Err(EncodingError::invalid_data(&format!(
                    "Could not decode MsgData. The first byte [{req_resp_flag}] did not match the request [{REQUEST_ID}] or response [{RESPONSE_ID}] flags"
                )));
            }
        })
    }
}
