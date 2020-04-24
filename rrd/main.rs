#![warn(elided_lifetimes_in_paths)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]

//! Experimental [Ripple](https://ripple.com/) node on [Rust](https://www.rust-lang.org/).
//! Based on [rippled](https://github.com/ripple/rippled/), crated as learning project.

use network::Network;

mod args;

/// Start Rust Ripple node.
fn main() {
    logj::init();
    let _args = args::get_args();

    let mut runtime = tokio::runtime::Builder::new()
        .core_threads(num_cpus::get())
        .enable_io()
        .enable_time()
        .threaded_scheduler()
        .build()
        .expect("Building runtime");

    let mut network = Network::new();
    if let Err(error) = runtime.block_on(network.run()) {
        logj::error!("{}", error);
        std::process::exit(1);
    }

    std::process::exit(0);
}
