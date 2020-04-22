#![warn(elided_lifetimes_in_paths)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]

//! Crypto structs and functions used in ripple protocol.

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate quick_error;

// re-export internal
pub use secp256k1;
pub use sha2;

// re-export own
pub use secp256k1_keys::Secp256k1Keys;

mod secp256k1_keys;

// static secp256k1 context
lazy_static! {
    /// Initialized Secp256k1 context with all capabilities
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}
