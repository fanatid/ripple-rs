use bytes::{Buf, BytesMut};
use crypto::sha2::{Digest, Sha512};
use crypto::{secp256k1::Message, Secp256k1Keys};
use openssl::ssl::SslRef;
use tokio::io::{AsyncRead, AsyncReadExt};

fn get_message(ssl: &SslRef) -> Message {
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
pub(crate) fn create_signature(ssl: &SslRef, keys: &Secp256k1Keys) -> String {
    let msg = get_message(ssl);
    let sig = keys.sign(&msg).serialize_der();
    base64::encode(&sig)
}

// pub(crate) fn verify_signature

pub(crate) async fn read_response<T: AsyncRead>(
    stream: &mut T,
) -> Result<(u16, BytesMut), Box<dyn std::error::Error>> {
    let mut buf = BytesMut::new();
    let code = loop {
        if stream.read_buf(&mut buf).await? == 0 {
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
        while stream.read_buf(&mut buf).await? > 0 {}
    }

    Ok((code, buf))
}
