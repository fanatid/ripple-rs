use std::borrow::Cow;

use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, SecretKey, Signature};

use super::SECP256K1;

/// Simplified interface to [`secp256k1`][secp256k1] crate.
#[derive(Debug)]
pub struct Secp256k1Keys {
    secret_key: SecretKey,
    public_key: PublicKey,
    public_key_bs58: String,
}

impl Secp256k1Keys {
    /// Create new Secp256k1 random key-pair.
    pub fn random() -> Secp256k1Keys {
        let mut rng = OsRng::new().expect("Create OsRng");
        let secret_key = SecretKey::new(&mut rng);
        Self::from_secret_key(secret_key)
    }

    /// Create struct from serialized SecretKey in hex.
    pub fn from_hex<T: AsRef<[u8]>>(data: T) -> Result<Secp256k1Keys, KeysError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(data, &mut bytes).map_err(|_| KeysError::InvalidSecretKeyHex)?;
        let secret_key = SecretKey::from_slice(&bytes).map_err(|_| KeysError::InvalidSecretKey)?;
        Ok(Self::from_secret_key(secret_key))
    }

    /// Create struct from SecretKey.
    fn from_secret_key(secret_key: SecretKey) -> Secp256k1Keys {
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key);

        let serialized = public_key.serialize();
        let public_key_bs58 = bs58::encode(bs58::Version::NodePublic, &serialized[..]);

        Secp256k1Keys {
            secret_key,
            public_key,
            public_key_bs58,
        }
    }

    /// Serialize PublicKey to base58.
    pub fn get_public_key_bs58(&self) -> Cow<'_, String> {
        Cow::Borrowed(&self.public_key_bs58)
    }

    /// Sign [`secp256k1::Message`][secp256k1::Message].
    pub fn sign(&self, msg: &Message) -> Signature {
        SECP256K1.sign(msg, &self.secret_key)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum KeysError {
        InvalidSecretKeyHex {
            display("Invalid Secret Key in hex")
        }
        InvalidSecretKey {
            display("Invalid Secret Key")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_public_key_bs58() {
        let data = "e55dc8f3741ac9668dbe858409e5d64f5ce88380f7228eccfe82b92b2c7848ba";

        let keys = Secp256k1Keys::from_hex(data);
        assert_eq!(keys.is_ok(), true);

        let keys = keys.unwrap();
        assert_eq!(
            &*keys.get_public_key_bs58(),
            "n9KAa2zVWjPHgfzsE3iZ8HAbzJtPrnoh4H2M2HgE7dfqtvyEb1KJ"
        )
    }
}
