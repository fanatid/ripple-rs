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

#[macro_use]
extern crate quick_error;

use std::net::SocketAddr;
use std::sync::Arc;

use crypto::Secp256k1Keys;
use futures::future::join_all;
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

    /// Connect to resolved nodes.
    pub async fn connect(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addrs = Self::get_bootstrap_addrs().await;

        for addr in addrs {
            if addr.is_ipv4() {
                match Peer::from_addr(addr, self.node_key.clone()).await {
                    Ok(mut peer) => match peer.connect().await {
                        Ok(_) => loop {
                            let msg = peer.read_message().await?;
                            let dbg = format!("{:?}", msg);
                            println!("Received: {:?}", dbg.split('(').next().unwrap());
                        },
                        Err(peer::HandshakeError::Unavailable(ips)) => {
                            logj::info!("Unavailable peer: {}. Provide peers: {:?}", addr, ips);
                            // addrs.append(&mut ips);
                        }
                        Err(error) => {
                            logj::error!("Failed handshake with peer {}: {}", addr, error);
                        }
                    },
                    Err(error) => {
                        logj::error!("Failed connect to peer {}: {}", addr, error);
                    }
                };
            }
        }

        Ok(())
    }

    /// Return pre-defined nodes.
    /// https://github.com/ripple/rippled/blob/1.5.0/src/ripple/overlay/impl/OverlayImpl.cpp#L536-L544
    const fn get_bootstrap_nodes() -> [&'static str; 3] {
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
    async fn get_bootstrap_addrs() -> Vec<SocketAddr> {
        let nodes = Self::get_bootstrap_nodes();

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
