use std::net::TcpListener;

use crate::{Peer, Result, cenc::validate_id};
pub fn free_port() -> Option<u16> {
    match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(listener) => {
            // Get the port number that was assigned
            match listener.local_addr() {
                Ok(addr) => Some(addr.port()),
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

#[test]
fn test_validate_id() -> Result<()> {
    let id: [u8; 32] = [
        128, 153, 111, 213, 115, 62, 11, 125, 92, 62, 223, 183, 3, 135, 211, 39, 152, 41, 73, 55,
        160, 113, 55, 48, 114, 90, 50, 44, 201, 131, 192, 94,
    ];
    let from = Peer {
        id: None,
        referrer: None,
        addr: "188.166.28.20:60692".parse()?,
    };
    assert!(validate_id(&Some(id), &from).is_some());
    Ok(())
}
