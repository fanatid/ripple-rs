#![warn(elided_lifetimes_in_paths)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unreachable_pub)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]

//! Base58 encode/decode for Ripple, with checks and prefixes.

/// Data prefix.
/// https://github.com/ripple/rippled/blob/1.5.0/src/ripple/protocol/tokens.h#L29-L39
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Version {
    // None,
    NodePublic,
    NodePrivate,
    AccountID,
    AccountPublic,
    AccountSecret,
    // FamilyGenerator,
    FamilySeed,
}

impl Version {
    /// Resolve enum variant to `u8`.
    pub fn value(&self) -> u8 {
        match *self {
            // Version::None => 1,
            Version::NodePublic => 28,
            Version::NodePrivate => 32,
            Version::AccountID => 0,
            Version::AccountPublic => 35,
            Version::AccountSecret => 34,
            // Version::FamilyGenerator => 41,
            Version::FamilySeed => 33,
        }
    }
}

/// Encode given input with prefix to base58-check based on Ripple alphabet.
pub fn encode<I: AsRef<[u8]>>(version: Version, input: I) -> String {
    bs58::encode(input)
        .with_prepared_alphabet(bs58::Alphabet::RIPPLE)
        .with_check_version(version.value())
        .into_string()
}

/// Decode given input in base58-check based on Ripple alphabet.
pub fn decode<I: AsRef<[u8]>>(version: Version, input: I) -> bs58::decode::Result<Vec<u8>> {
    bs58::decode(input)
        .with_prepared_alphabet(bs58::Alphabet::RIPPLE)
        .with_check(Some(version.value()))
        .into_vec()
        .map(|mut vec| {
            let _ = vec.remove(0);
            vec
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_public() {
        let data = "n9KAa2zVWjPHgfzsE3iZ8HAbzJtPrnoh4H2M2HgE7dfqtvyEb1KJ";

        let bytes = decode(Version::NodePublic, &data);
        assert!(bytes.is_ok());

        let bytes = bytes.unwrap();
        let value = encode(Version::NodePublic, &bytes);
        assert_eq!(value, data);
    }
}
