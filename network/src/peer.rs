use std::net::SocketAddr;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, Bytes, BytesMut};
use crypto::sha2::{Digest, Sha512};
use crypto::{secp256k1::Message, Secp256k1Keys};
use openssl::ssl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tls::TlsStream;

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
    // node_key as ref?
    node_key: Arc<Secp256k1Keys>,
    stream: TlsStream<TcpStream>,
    read_buf: BytesMut,
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
    ) -> Result<Peer, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        let cx = native_tls::TlsConnector::builder()
            .use_sni(false)
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()?;
        let cx = tokio_tls::TlsConnector::from(cx);
        let stream = cx.connect("", stream).await?;

        Ok(Peer {
            node_key,
            stream,
            read_buf: BytesMut::with_capacity(128 * 1024),
        })
    }

    /// Sned handshake message and run read messages loop if handshake successful.
    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.handshake_send_request().await?;

        let (code, body) = self.handshake_read_response().await?;
        match code {
            101 => {}
            503 => panic!("More peers..."),
            _ => {
                panic!("Code: {}, body: {}", code, String::from_utf8_lossy(&body));
            }
        };

        // TODO: save `body` as extra readed bytes

        Ok(())
    }

    async fn handshake_send_request(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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
            create_signature(self.get_sslref(), &self.node_key)
        );
        self.stream.write_all(content.as_bytes()).await?;

        Ok(())
    }

    async fn handshake_read_response(
        &mut self,
    ) -> Result<(u16, BytesMut), Box<dyn std::error::Error>> {
        let mut buf = BytesMut::new();
        let code = loop {
            if self.stream.read_buf(&mut buf).await? == 0 {
                println!(
                    "Current buffer: {}",
                    String::from_utf8_lossy(buf.bytes()).trim()
                );
                panic!("socket closed");
            }

            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut resp = httparse::Response::new(&mut headers);
            let status = resp.parse(&buf).expect("response parse success");
            if status.is_complete() {
                let code = resp.code.unwrap();
                buf.advance(status.unwrap());
                break code;
            }
        };

        if code != 101 {
            while self.stream.read_buf(&mut buf).await? > 0 {}
        }

        Ok((code, buf))
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

    /// Read message from peer.
    pub async fn read_message(&mut self) -> Result<protocol::Message, Box<dyn std::error::Error>> {
        // TODO: fiture out buffer required for most of messages.
        loop {
            match self.stream.read_buf(&mut self.read_buf).await {
                Ok(size) => {
                    if size == 0 {
                        println!(
                            "Current buffer: {}",
                            String::from_utf8_lossy(self.read_buf.bytes()).trim()
                        );
                        panic!("socket closed");
                    }
                }
                Err(error) => {
                    panic!("Socket read error: {}", error);
                }
            }

            if self.read_buf.len() > 6 {
                let bytes = self.read_buf.bytes();

                if bytes[0] & 0xFC != 0 {
                    panic!("Unknow version header");
                }

                let payload_size = BigEndian::read_u32(&bytes[0..4]) as usize;
                let message_type = BigEndian::read_u16(&bytes[4..6]);

                if payload_size > 64 * 1024 * 1024 {
                    panic!("Too big message size");
                }

                if self.read_buf.len() >= 6 + payload_size {
                    let bytes = Bytes::copy_from_slice(&self.read_buf.bytes()[6..6 + payload_size]);
                    let msg = protocol::Message::decode(message_type as i32, bytes)?;
                    self.read_buf.advance(6 + payload_size);
                    return Ok(msg);
                }
            }
        }
    }

    // pub async fn send_message(&self, ?) -> Result<(), ?> {
    //     self.stream.lock()
    // }
}

fn get_shared_message(ssl: &ssl::SslRef) -> Message {
    let mut buf = Vec::<u8>::with_capacity(1024);
    buf.resize(buf.capacity(), 0);

    let mut size = ssl.finished(&mut buf[..]);
    if size > buf.len() {
        buf.resize(size, 0);
        size = ssl.finished(&mut buf[..]);
    }
    let cookie1 = Sha512::digest(&buf[..size]);

    let mut size = ssl.peer_finished(&mut buf[..]);
    if size > buf.len() {
        buf.resize(size, 0);
        size = ssl.peer_finished(&mut buf[..]);
    }
    let cookie2 = Sha512::digest(&buf[..size]);

    let mix = cookie1
        .iter()
        .zip(cookie2.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();
    Message::from_slice(&Sha512::digest(&mix[..])[0..32]).expect("Invalid secp256k1::Message")
}

/// Create base64 encoded signature for handshake.
pub(crate) fn create_signature(ssl: &ssl::SslRef, keys: &Secp256k1Keys) -> String {
    let msg = get_shared_message(ssl);
    let sig = keys.sign(&msg).serialize_der();
    base64::encode(&sig)
}
