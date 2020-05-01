#![warn(elided_lifetimes_in_paths)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]

//! Our bridge to ripple network.

#![feature(ip)]

#[macro_use]
extern crate quick_error;

use std::net::SocketAddr;
use std::sync::Arc;

use crypto::Secp256k1Keys;

pub use peer::Peer;
pub use peer_table::PeerTable;

mod peer;
mod peer_table;

/// Peers collection and communication through ripple protocol.
#[derive(Debug)]
pub struct Network {
    // nodes_max: usize,
    // peers: Vec<Peer>,
    node_key: Arc<Secp256k1Keys>,
    peer_table: Arc<PeerTable>,
}

impl Network {
    /// Create new Network.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Network {
        Network {
            // nodes_max: 1,
            // peers: vec![],
            node_key: Arc::new(Secp256k1Keys::random()),
            peer_table: Arc::new(PeerTable::default()),
        }
    }

    /// Start network. Resolve nodes addrs, connect and communicate.
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.peer_table.load_peer_addrs().await;

        let peer = loop {
            let addr = match self.peer_table.get_peer_address().await {
                Some(addr) => addr,
                None => break None,
            };

            match self.connect_to(addr).await {
                Ok(peer) => break Some(peer),
                Err(PeerError::Connect(error)) => {
                    logj::error!("Failed connect to peer {}: {}", addr, error)
                }
                Err(PeerError::Handshake(error)) => {
                    logj::error!("Failed handshake with peer {}: {}", addr, error);
                }
                Err(PeerError::Unavailable(ips)) => {
                    logj::error!("Peer unavailable, give {} peers", ips.len());
                    self.peer_table.on_redirect(ips).await;
                }
            }
        };
        if peer.is_none() {
            panic!("Was not able connect to any peer");
        }

        // temporary...
        tokio::time::delay_for(std::time::Duration::from_secs(24 * 60 * 60)).await;

        Ok(())
    }

    /// Connect to address.
    pub async fn connect_to(&self, addr: SocketAddr) -> Result<Arc<Peer>, PeerError> {
        match Peer::from_addr(
            addr,
            Arc::clone(&self.node_key),
            Arc::clone(&self.peer_table),
        )
        .await
        {
            Ok(peer) => match peer.connect().await {
                Ok(_) => Ok(peer),
                Err(peer::HandshakeError::Unavailable(ips)) => Err(PeerError::Unavailable(ips)),
                Err(error) => Err(PeerError::Handshake(error)),
            },
            Err(error) => Err(PeerError::Connect(error)),
        }
    }
}

quick_error! {
    /// Possible peer errors.
    #[allow(missing_docs)]
    #[derive(Debug)]
    pub enum PeerError {
        Connect(error: peer::ConnectError) {
            display("{}", error)
        }
        Handshake(error: peer::HandshakeError) {
            display("{}", error)
        }
        Unavailable(ips: Vec<SocketAddr>) {
            display("Unavailable, give peers: {:?}", ips)
        }
    }
}

/// Ripple support [`Parallel Networks`](https://xrpl.org/parallel-networks.html),
/// this used for network identification.
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq)]
pub enum NetworkId {
    Main,
    Test,
    Other(u32),
}

impl NetworkId {
    /// Network id represented by 32-bit unsigned integer.
    pub fn value(&self) -> u32 {
        match *self {
            NetworkId::Main => 0,
            NetworkId::Test => 1,
            NetworkId::Other(id) => id,
        }
    }
}

impl std::str::FromStr for NetworkId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.parse::<u32>()? {
            0 => NetworkId::Main,
            1 => NetworkId::Test,
            id => NetworkId::Other(id),
        })
    }
}
