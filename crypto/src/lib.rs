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

//! Crypto structs and functions used in ripple protocol.

#[macro_use]
extern crate lazy_static;

// re-export
pub use secp256k1;
pub use sha2;

// Create Secp256k1 context.
use secp256k1::{All, Secp256k1};
lazy_static! {
    /// Initialized Secp256k1 context with all capabilities
    pub static ref SECP256K1: Secp256k1<All> = Secp256k1::new();
}
