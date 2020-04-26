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
use futures::future::join_all;
use rand::seq::SliceRandom;
use tokio::net::lookup_host;

pub use peer::Peer;

mod peer;

/// Peers collection and communication through ripple protocol.
#[derive(Debug)]
pub struct Network {
    // nodes_max: usize,
    // peers: Vec<Peer>,
    node_key: Arc<Secp256k1Keys>,
}

impl Network {
    /// Create new Network.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Network {
        Network {
            // nodes_max: 1,
            // peers: vec![],
            node_key: Arc::new(Secp256k1Keys::random()),
        }
    }

    /// Start network. Resolve nodes addrs, connect and communicate.
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut addrs = Self::load_peer_addrs().await;

        let peer = loop {
            addrs.shuffle(&mut rand::thread_rng());
            let addr = match addrs.pop() {
                Some(addr) => addr,
                None => break None,
            };
            if addr.is_ipv6() {
                continue;
            }

            match self.connect_to(addr).await {
                Ok(peer) => break Some(peer),
                Err(PeerError::Connect(error)) => {
                    logj::error!("Failed connect to peer {}: {}", addr, error)
                }
                Err(PeerError::Handshake(error)) => {
                    logj::error!("Failed handshake with peer {}: {}", addr, error);
                }
                Err(PeerError::Unavailable(mut ips)) => {
                    addrs.append(&mut ips);
                    addrs.dedup();
                    logj::error!("Peer unavailable, give {} peers", ips.len());
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

    /// Connect to resolved nodes.
    pub async fn connect_to(&self, addr: SocketAddr) -> Result<Arc<Peer>, PeerError> {
        match Peer::from_addr(addr, self.node_key.clone()).await {
            Ok(peer) => match peer.connect().await {
                Ok(_) => Ok(peer),
                Err(peer::HandshakeError::Unavailable(ips)) => Err(PeerError::Unavailable(ips)),
                Err(error) => Err(PeerError::Handshake(error)),
            },
            Err(error) => Err(PeerError::Connect(error)),
        }
    }

    /// Return pre-defined nodes.
    /// https://github.com/ripple/rippled/blob/1.5.0/src/ripple/overlay/impl/OverlayImpl.cpp#L536-L544
    const fn get_bootstrap_peer_nodes() -> [&'static str; 3] {
        [
            // Pool of servers operated by Ripple Labs Inc. - https://ripple.com
            "r.ripple.com:51235",
            // Pool of servers operated by Alloy Networks - https://www.alloy.ee
            "zaphod.alloy.ee:51235",
            // Pool of servers operated by ISRDC - https://isrdc.in
            "sahyadri.isrdc.in:51235",
        ]
    }

    /// Resolve nodes to addrs.
    async fn get_bootstrap_peer_addrs() -> Vec<SocketAddr> {
        let nodes = Self::get_bootstrap_peer_nodes();

        let futs = nodes.iter().map(|node| async move {
            match lookup_host(node).await {
                Ok(addrs) => addrs.collect(),
                Err(error) => {
                    logj::error!("Failed resolve bootstrap node {}: {}", node, error);
                    vec![]
                }
            }
        });
        let addrs = join_all(futs).await;
        addrs.into_iter().flatten().collect()
    }

    /// Load peers addresses from storage or use bootstrap addresses.
    async fn load_peer_addrs() -> Vec<SocketAddr> {
        // TODO: load from storage
        let mut addrs = Self::get_bootstrap_peer_addrs().await;
        addrs.dedup();
        addrs
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
