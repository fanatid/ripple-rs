use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, Bytes, BytesMut};
use crypto::secp256k1::{Message, PublicKey, Signature};
use crypto::sha2::{Digest, Sha512};
use crypto::Secp256k1Keys;
use openssl::ssl::{SslRef, SslStream};
use serde::{de, Deserialize, Deserializer, Serialize};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use tokio_tls::TlsStream;

use super::NetworkId;

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
    msg_tx: UnboundedSender<Result<protocol::Message, SendRecvError>>,
    network_id: NetworkId,
    //
    peer_addr: SocketAddr,
    // connection is complete mess right now, move to own struct
    // (mix of openssl + TcpStream + ReadHalf/WriteHalf + BufStream?)
    ssl: &'static SslRef,
    stream_tx: Mutex<tokio::io::WriteHalf<TlsStream<TcpStream>>>,
    stream_rx: Mutex<tokio::io::ReadHalf<TlsStream<TcpStream>>>,
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
        msg_tx: UnboundedSender<Result<protocol::Message, SendRecvError>>,
    ) -> Result<Arc<Peer>, ConnectError> {
        let stream = TcpStream::connect(addr).await.map_err(ConnectError::Io)?;
        stream.set_nodelay(true).map_err(ConnectError::Io)?;

        let cx = native_tls::TlsConnector::builder()
            .use_sni(false)
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(ConnectError::Tls)?;
        let cx = tokio_tls::TlsConnector::from(cx);
        let stream = cx.connect("", stream).await.map_err(ConnectError::Tls)?;

        let peer_addr = stream.get_ref().peer_addr().unwrap();
        let ssl = unsafe {
            // TODO: use openssl directly, without tokio_tls and native-tls
            // https://docs.rs/tokio-tls/0.3.0/src/tokio_tls/lib.rs.html#43-47
            // AllowStd have size 64
            #[allow(trivial_casts)]
            (*(&stream as *const _ as *const SslStream<[u8; 64]>)).ssl()
        };

        let (stream_rx, stream_tx) = tokio::io::split(stream);

        Ok(Arc::new(Peer {
            node_key,
            msg_tx,
            network_id: NetworkId::Main,
            peer_addr,
            ssl,
            stream_tx: Mutex::new(stream_tx),
            stream_rx: Mutex::new(stream_rx),
        }))
    }

    /// Outgoing handshake process.
    pub async fn connect(self: &Arc<Peer>) -> Result<(), HandshakeError> {
        self.handshake_send_request().await?;
        self.handshake_read_response().await?;
        Peer::read_messages(Arc::clone(&self));
        Ok(())
    }

    /// Send handshake request.
    async fn handshake_send_request(&self) -> Result<(), HandshakeError> {
        let mut content = format!(
            "\
            GET / HTTP/1.1\r\n\
            User-Agent: rrd-0.0.0\r\n\
            Connection: Upgrade\r\n\
            Upgrade: XRPL/2.0\r\n\
            Connect-As: Peer\r\n\
            Network-ID: {}\r\n\
            Network-Time: {}\r\n\
            Public-Key: {}\r\n\
            Session-Signature: {}\r\n\
            Crawl: private\r\n",
            self.network_id.value(),
            network_time(),
            self.node_key.get_public_key_bs58(),
            self.handshake_create_signature()?
        );

        let remote = self.peer_addr.ip();
        if remote.is_global() {
            content += &format!("Remote-IP: {}\r\n", remote);
        }

        // specified global ip from config
        // Local-IP: {}

        // Closed-Ledger: {}
        // Previous-Ledger: {}

        content += "\r\n";

        let mut stream = self.stream_tx.lock().await;
        let fut = stream.write_all(content.as_bytes());
        fut.await.map_err(HandshakeError::Io)
    }

    /// Read peer handshake response for our handshake request.
    async fn handshake_read_response(&self) -> Result<(), HandshakeError> {
        let mut buf = BytesMut::new();

        let mut stream = self.stream_rx.lock().await;
        let code = loop {
            let fut = stream.read_buf(&mut buf);
            if fut.await.map_err(HandshakeError::Io)? == 0 {
                return Err(HandshakeError::EndOfFile);
            }

            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut resp = httparse::Response::new(&mut headers);
            let status = resp.parse(&buf).expect("response parse success");
            if status.is_partial() {
                continue;
            }

            let code = resp.code.unwrap();
            if code == 101 {
                let find_header = |name| {
                    resp.headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case(name))
                        .map(|h| String::from_utf8_lossy(h.value))
                };

                let get_header =
                    |name| find_header(name).ok_or_else(|| HandshakeError::MissingHeader(name));

                // self.peer_user_agent = Some(get_header!("Server").to_string());
                let _ = get_header("Server")?;

                if get_header("Connection")? != "Upgrade" {
                    let reason = r#"expect "Upgrade""#.to_owned();
                    return Err(HandshakeError::InvalidHeader("Connection", reason));
                }

                if get_header("Upgrade")? != "XRPL/2.0" {
                    let reason = r#"Only "XRPL/2.0" supported right now"#.to_owned();
                    return Err(HandshakeError::InvalidHeader("Upgrade", reason));
                }

                if !get_header("Connect-As")?.eq_ignore_ascii_case("peer") {
                    let reason = r#"Only "Peer" supported right now"#.to_owned();
                    return Err(HandshakeError::InvalidHeader("Connect-As", reason));
                }

                if let Some(value) = find_header("Remote-IP") {
                    let parsed = value.parse::<IpAddr>();
                    let _ip = parsed.map_err(|e| HandshakeError::InvalidRemoteIp(e.to_string()))?;

                    // if ip.is_global() && `public ip specified in config` && ip != `specified global ip from config` {
                    //     let reason = format!("{} instead of {}", ip, ?);
                    //     return Err(HandshakeError::InvalidRemoteIp(reason));
                    // }
                }

                if let Some(value) = find_header("Local-IP") {
                    let parsed = value.parse::<IpAddr>();
                    let ip = parsed.map_err(|e| HandshakeError::InvalidLocalIp(e.to_string()))?;

                    let remote = self.peer_addr.ip();
                    if remote.is_global() && remote != ip {
                        let reason = format!("{} instead of {}", ip, remote);
                        return Err(HandshakeError::InvalidLocalIp(reason));
                    }
                }

                let network_id = match find_header("Network-Id") {
                    Some(value) => value
                        .parse::<NetworkId>()
                        .map_err(|e| HandshakeError::InvalidNetworkId(e.to_string()))?,
                    None => NetworkId::Main,
                };
                if network_id != self.network_id {
                    let expected = self.network_id.value();
                    let received = network_id.value();
                    let reason = format!("{} instead of {}", received, expected);
                    return Err(HandshakeError::InvalidNetworkId(reason));
                }

                if let Some(value) = find_header("Network-Time") {
                    let peer_time = value
                        .parse::<u64>()
                        .map_err(|e| HandshakeError::InvalidNetworkTime(e.to_string()))?;
                    let local_time = network_time();

                    use std::cmp::{max, min};
                    let diff = max(peer_time, local_time) - min(peer_time, local_time);
                    if diff > 20 {
                        let reason = "Peer clock is too far off".to_owned();
                        return Err(HandshakeError::InvalidNetworkTime(reason));
                    }
                }

                let public_key = get_header("Public-Key")?;
                let sig = get_header("Session-Signature")?;
                // self.peer_public_key = Some(self.handshake_verify_signature(sig, public_key)?);
                let _ = self.handshake_verify_signature(sig, public_key)?;

            // Crawl public
            // Closed-Ledger W8hR7+Q1acWpc1fcKXA6J0Qa9pmJ4dxjvKkacx/6GC8=
            // Previous-Ledger b2+kJlTVmP0zXTirE570dWaTSFDfnTM/fOftA2UoCxM=
            } else {
                loop {
                    let fut = stream.read_buf(&mut buf);
                    if fut.await.map_err(HandshakeError::Io)? == 0 {
                        break;
                    }
                }

                // chunked-encoding...
                let mut buf1 = buf.clone();
                let mut buf2 = BytesMut::with_capacity(buf.len());
                while !buf1.is_empty() {
                    let status = match httparse::parse_chunk_size(&buf1) {
                        Ok(status) => status,
                        Err(_) => return Err(HandshakeError::InvalidChunkedBody(buf)),
                    };

                    if status.is_partial() {
                        return Err(HandshakeError::InvalidChunkedBody(buf));
                    }

                    let (start, size) = status.unwrap();
                    if size == 0 {
                        break;
                    }

                    let end = start + size as usize;
                    buf2.extend_from_slice(&buf1.bytes()[start..end]);
                    buf1.advance(end);
                }

                buf = buf2;
            }

            buf.advance(status.unwrap());
            break code;
        };

        match code {
            101 => {
                if !buf.is_empty() {
                    panic!("Read more data than expected on successful handshake...");
                }

                Ok(())
            }
            400 => Err(HandshakeError::BadRequest(
                String::from_utf8_lossy(&buf).trim().to_string(),
            )),
            503 => match serde_json::from_slice::<PeerUnavailableBody>(&buf) {
                Ok(body) => Err(HandshakeError::Unavailable(body.ips)),
                Err(_) => Err(HandshakeError::UnavailableBadBody(
                    String::from_utf8_lossy(&buf).to_string(),
                )),
            },
            _ => Err(HandshakeError::UnexpectedHttpStatus(code)),
        }
    }

    /// Create message for create/verify signature.
    fn handshake_mkshared(&self) -> Result<Message, HandshakeError> {
        let mut buf = Vec::<u8>::with_capacity(1024);
        buf.resize(buf.capacity(), 0);

        let mut size = self.ssl.finished(&mut buf[..]);
        if size > buf.len() {
            buf.resize(size, 0);
            size = self.ssl.finished(&mut buf[..]);
        }
        let cookie1 = Sha512::digest(&buf[..size]);

        let mut size = self.ssl.peer_finished(&mut buf[..]);
        if size > buf.len() {
            buf.resize(size, 0);
            size = self.ssl.peer_finished(&mut buf[..]);
        }
        let cookie2 = Sha512::digest(&buf[..size]);

        let mix = cookie1
            .iter()
            .zip(cookie2.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();
        let hash = Sha512::digest(&mix[..]);

        Message::from_slice(&hash[0..32]).map_err(|_| HandshakeError::InvalidMessage)
    }

    /// Create base64 encoded signature for handshake with node keys ([`Secp256k1Keys`][crypto::Secp256k1Keys]).
    fn handshake_create_signature(&self) -> Result<String, HandshakeError> {
        let msg = self.handshake_mkshared()?;
        let sig = self.node_key.sign(&msg).serialize_der();
        Ok(base64::encode(&sig))
    }

    /// Verify base64 encoded signature for handshake with base58 encoded Public Key.
    /// Return [`PublicKey`][crypto::secp256k1::PublicKey] on success.
    fn handshake_verify_signature(
        &self,
        sig_header: Cow<'_, str>,
        pk_header: Cow<'_, str>,
    ) -> Result<PublicKey, HandshakeError> {
        let pk_bytes = bs58_ripple::decode(bs58_ripple::Version::NodePublic, &*pk_header)
            .map_err(|_| HandshakeError::InvalidPublicKey(pk_header.to_string()))?;
        let pk = PublicKey::from_slice(&pk_bytes)
            .map_err(|_| HandshakeError::InvalidPublicKey(pk_header.to_string()))?;

        let sig_bytes = base64::decode(&*sig_header)
            .map_err(|_| HandshakeError::InvalidSignature(sig_header.to_string()))?;
        let sig = Signature::from_der(&sig_bytes)
            .map_err(|_| HandshakeError::InvalidSignature(sig_header.to_string()))?;

        let msg = self.handshake_mkshared()?;
        match crypto::SECP256K1.verify(&msg, &sig, &pk) {
            Ok(_) => Ok(pk),
            Err(_) => Err(HandshakeError::SignatureVerificationFailed),
        }
    }

    /// Read message from peer.
    fn read_messages(self: Arc<Peer>) {
        let _join_handle = tokio::spawn(async move {
            // TODO: fiture out buffer required for most of messages.
            let mut buf = BytesMut::new();
            let mut stream = self.stream_rx.lock().await;

            loop {
                match stream.read_buf(&mut buf).await {
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

                if buf.len() > 6 {
                    let bytes = buf.bytes();

                    if bytes[0] & 0xFC != 0 {
                        panic!("Unknow version header");
                    }

                    let payload_size = BigEndian::read_u32(&bytes[0..4]) as usize;
                    let message_type = BigEndian::read_u16(&bytes[4..6]);

                    if payload_size > 64 * 1024 * 1024 {
                        panic!("Too big message size");
                    }

                    if buf.len() >= 6 + payload_size {
                        let bytes = Bytes::copy_from_slice(&buf.bytes()[6..6 + payload_size]);
                        let msg = protocol::Message::decode(message_type as i32, bytes)
                            .map_err(|_| SendRecvError::Decode);
                        buf.advance(6 + payload_size);

                        self.msg_tx.send(msg).unwrap();
                    }
                }
            }
        });
    }

    // pub async fn send_message(&self, ?) -> Result<(), ?> {
    //     // should lock `stream_tx`, otherwise other fut can produce mixed write
    //     self.stream.lock()
    // }
}

quick_error! {
    /// Possible errors on connecting to peer.
    #[derive(Debug)]
    pub enum ConnectError {
        Io(error: io::Error) {
            display("{}", error)
        }
        Tls(error: native_tls::Error) {
            display("{}", error)
        }
    }
}

quick_error! {
    /// Possible errors during handshake process.
    #[derive(Debug)]
    pub enum HandshakeError {
        Io(error: io::Error) {
            display("{}", error)
        }
        EndOfFile {
            display("Socket reached end-of-file")
        }
        MissingHeader(name: &'static str) {
            display(r#"Header "{}" required"#, name)
        }
        InvalidHeader(name: &'static str, reason: String) {
            display(r#"Invalid header "{}": {}"#, name, reason)
        }
        InvalidNetworkId(reason: String) {
            display("Invalid network id: {}", reason)
        }
        InvalidNetworkTime(reason: String) {
            display("Invalid network time: {}", reason)
        }
        InvalidRemoteIp(reason: String) {
            display("Invalid remote ip: {}", reason)
        }
        InvalidLocalIp(reason: String) {
            display("Invalid local ip: {}", reason)
        }
        InvalidMessage {
            display("Invalid message generated")
        }
        InvalidPublicKey(public_key: String) {
            display(r#"Invalid Public Key: "{}""#, public_key)
        }
        InvalidSignature(sig: String) {
            display(r#"Invalid Signature: "{}""#, sig)
        }
        SignatureVerificationFailed {
            display("Signature verification failed")
        }
        InvalidChunkedBody(body: BytesMut) {
            display("Invalid chunked body: {:?}", &body.bytes())
        }
        BadRequest(reason: String) {
            display("Bad request: {}", reason)
        }
        Unavailable(ips: Vec<SocketAddr>) {
            display("Unavailable, give peers: {:?}", ips)
        }
        UnavailableBadBody(body: String) {
            display("Unavailable, can't parse body: {}", body)
        }
        UnexpectedHttpStatus(status: u16) {
            display("Unexpected HTTP status: {}", status)
        }
    }
}

quick_error! {
    /// Possible errors on read/write.
    #[derive(Debug)]
    pub enum SendRecvError {
        Io(error: io::Error) {
            display("{}", error)
        }
        Decode {
            display("")
        }
    }
}

/// If peer response with 503 (unavailable) on handshake, in body we receive
#[derive(Debug, Deserialize, Serialize)]
struct PeerUnavailableBody {
    #[serde(
        rename = "peer-ips",
        deserialize_with = "PeerUnavailableBody::ips_deserialize"
    )]
    pub ips: Vec<SocketAddr>,
}

impl PeerUnavailableBody {
    #[allow(single_use_lifetimes)]
    fn ips_deserialize<'de, D>(deserializer: D) -> Result<Vec<SocketAddr>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut raw: Vec<&str> = Deserialize::deserialize(deserializer)?;

        let mut addrs = Vec::with_capacity(raw.len());
        for data in raw.iter_mut() {
            match SocketAddr::from_str(data) {
                Ok(addr) => addrs.push(addr),
                Err(error) => {
                    return Err(de::Error::invalid_value(
                        de::Unexpected::Other(&format!("{}", error)),
                        &"an Array of SocketAddr",
                    ))
                }
            }
        }
        Ok(addrs)
    }
}

/// Get Ripple time ([docs](https://xrpl.org/basic-data-types.html#specifying-time)).
fn network_time() -> u64 {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("You came from the past")
        .checked_sub(Duration::from_secs(946_684_800)) // 10_957 (days) * 86_400 (seconds)
        .expect("You came from the past")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_ips_decode_encode() {
        let data = r#"{"peer-ips":["54.68.219.39:51235","54.187.191.179:51235"]}"#;

        let body = serde_json::from_str::<PeerUnavailableBody>(data);
        assert!(body.is_ok());
        let body = body.unwrap();

        let value = serde_json::to_string(&body);
        assert!(value.is_ok());
        assert_eq!(value.unwrap(), data);
    }
}
