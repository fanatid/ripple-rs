#![warn(elided_lifetimes_in_paths)]
#![warn(missing_debug_implementations)]
// #![warn(missing_docs)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
// #![warn(unreachable_pub)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]

//! Experimental [Ripple](https://ripple.com/) node on [Rust](https://www.rust-lang.org/).
//! Based on [rippled](https://github.com/ripple/rippled/), crated as learning project.

mod args;

fn main() {
    let args = args::Args::default();
    println!("{:?}", args.get_matches());
}
