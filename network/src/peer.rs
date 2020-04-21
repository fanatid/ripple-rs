use std::net::SocketAddr;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, Bytes, BytesMut};
use crypto::Secp256k1Keys;
use openssl::ssl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tls::TlsStream;

use super::handshake;

// /// Peer builder.
// #[derive(Debug)]
// pub struct PeerBuilder {
//     node_key: Option<Arc<Secp256k1Keys>>,
// }

// impl PeerBuilder {
//     pub fn node_key
// }

/// Single connection to ripple node.
#[derive(Debug)]
pub struct Peer {
    node_key: Arc<Secp256k1Keys>,
    stream: Mutex<TlsStream<TcpStream>>,
}

impl Peer {
    // Use PeerBuilder
    // pub fn builder() -> PeerBuilder
    // pub fn from_stream(stream: TlsStream<TcpStream>, node_key: Arc<Secp256k1Keys>) -> Result<Peer, std::convert::Infallible>
    // pub async fn send_unavailable(&mut self, addrs: Vec<SocketAddr>) -> Result<(), ?>
    // pub async fn accept(&mut self) -> Result<(), ?>

    /// Create [`Peer`][Peer] from given [`SocketAddr`][std::net::SocketAddr].
    pub async fn from_addr(
        addr: SocketAddr,
        node_key: Arc<Secp256k1Keys>,
    ) -> Result<Arc<Peer>, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        let cx = native_tls::TlsConnector::builder()
            .use_sni(false)
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()?;
        let cx = tokio_tls::TlsConnector::from(cx);
        let stream = cx.connect("", stream).await?;

        Ok(Arc::new(Peer {
            node_key,
            stream: Mutex::new(stream),
        }))
    }

    /// Sned handshake message and run read messages loop if handshake successful.
    pub async fn connect(self: &Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        let ss = self.get_sslref();

        let mut stream = self.stream.lock().await;
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

        let (code, body) = handshake::read_response(&mut *stream).await?;
        match code {
            101 => {}
            503 => panic!("More peers..."),
            _ => {
                panic!("Code: {}, body: {}", code, String::from_utf8_lossy(&body));
            }
        };

        // TODO: pass `body` as extra readed bytes
        self.read_messages();

        Ok(())
    }

    fn get_sslref(&self) -> &ssl::SslRef {
        unsafe {
            // TODO: use openssl directly, without tokio_tls and native-tls
            // https://docs.rs/tokio-tls/0.3.0/src/tokio_tls/lib.rs.html#43-47
            // AllowStd have size 64
            #[allow(trivial_casts)]
            (*(&self.stream as *const _ as *const ssl::SslStream<[u8; 64]>)).ssl()
        }
    }

    fn read_messages(self: &Arc<Self>) {
        let peer = Arc::clone(self);
        let _join_handle = tokio::spawn(async move {
            // TODO: fiture out buffer required for most of messages.
            // let mut buf = [0u8; 128 * 1024]; // 128 KiB
            let mut buf = BytesMut::new();
            loop {
                match peer.stream.lock().await.read_buf(&mut buf).await {
                    Ok(size) => {
                        if size == 0 {
                            println!(
                                "Current buffer: {}",
                                String::from_utf8_lossy(buf.bytes()).trim()
                            );
                            panic!("socket closed");
                        }
                    }
                    Err(error) => {
                        panic!("Socket read error: {}", error);
                    }
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

                    let bytes = Bytes::copy_from_slice(&buf.bytes()[6..6 + payload_size]);
                    let msg = protocol::Message::decode(message_type as i32, bytes);
                    println!("Received: {:?}", msg);
                    buf.advance(6 + payload_size);
                }
            }
        });
    }

    // pub async fn send_message(&self, ?) -> Result<(), ?> {
    //     self.stream.lock()
    // }
}
