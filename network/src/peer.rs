use std::net::SocketAddr;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use crypto::Secp256k1Keys;
use openssl::ssl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::handshake;

/// Single connection to ripple node.
#[derive(Debug)]
pub struct Peer {
    node_key: Arc<Secp256k1Keys>,
    addr: SocketAddr,
}

impl Peer {
    /// Create peer from [`SocketAddr`][std::net::SocketAddr].
    pub fn from_addr(addr: SocketAddr, node_key: Arc<Secp256k1Keys>) -> Peer {
        Peer { node_key, addr }
    }

    /// Attempt connect to peer.
    pub async fn connect(&self) -> Result<(), Box<dyn std::error::Error>> {
        let stream = tokio::net::TcpStream::connect(self.addr).await?;
        stream.set_nodelay(true)?;

        let cx = native_tls::TlsConnector::builder()
            .use_sni(false)
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()?;
        let cx = tokio_tls::TlsConnector::from(cx);
        let mut stream = cx.connect("", stream).await?;

        let ss = unsafe {
            // TODO: use openssl directly, without tokio_tls and native-tls
            // https://docs.rs/tokio-tls/0.3.0/src/tokio_tls/lib.rs.html#43-47
            // AllowStd have size 64
            #[allow(trivial_casts)]
            (*(&stream as *const _ as *const ssl::SslStream<[u8; 64]>)).ssl()
        };

        let content = format!(
            "\
            GET / HTTP/1.1\r\n\
            Upgrade: XRPL/2.0\r\n\
            Connection: Upgrade\r\n\
            Connect-As: Peer\r\n\
            Network-ID: 0\r\n\
            Public-Key: {}\r\n\
            Session-Signature: {}\r\n\
            \r\n",
            self.node_key.get_public_key_bs58(),
            handshake::create_signature(ss, &self.node_key)
        );
        stream.write_all(content.as_bytes()).await?;

        let (code, body) = handshake::read_response(&mut stream).await?;
        match code {
            101 => {}
            503 => panic!("More peers..."),
            _ => {
                panic!("Code: {}, body: {}", code, String::from_utf8_lossy(&body));
            }
        };

        let mut buf = BytesMut::new();
        loop {
            if stream.read_buf(&mut buf).await? == 0 {
                println!(
                    "Current buffer: {}",
                    String::from_utf8_lossy(buf.bytes()).trim()
                );
                panic!("socket closed");
            }

            while buf.len() > 6 {
                let bytes = buf.bytes();

                if bytes[0] & 0xFC != 0 {
                    panic!("Unknow version header");
                }

                let payload_size = BigEndian::read_u32(&bytes[0..4]) as usize;
                let message_type = BigEndian::read_u16(&bytes[4..6]);

                if payload_size > 64 * 1024 * 1024 {
                    panic!("Too big message size");
                }

                if buf.len() < 6 + payload_size {
                    break;
                }

                let tp = match message_type {
                    2 => "mtMANIFESTS",
                    3 => "mtPING",
                    5 => "mtCLUSTER",
                    15 => "mtENDPOINTS",
                    30 => "mtTRANSACTION",
                    31 => "mtGET_LEDGER",
                    32 => "mtLEDGER_DATA",
                    33 => "mtPROPOSE_LEDGER",
                    34 => "mtSTATUS_CHANGE",
                    35 => "mtHAVE_SET",
                    41 => "mtVALIDATION",
                    42 => "mtGET_OBJECTS",
                    50 => "mtGET_SHARD_INFO",
                    51 => "mtSHARD_INFO",
                    52 => "mtGET_PEER_SHARD_INFO",
                    53 => "mtPEER_SHARD_INFO",
                    54 => "mtVALIDATORLIST",
                    _ => "",
                };
                match tp {
                    "" => panic!("Received unknow message: {}", message_type),
                    _ => println!("Received message {}, size {}", tp, payload_size),
                }

                buf.advance(payload_size + 6);
            }
        }
    }
}
