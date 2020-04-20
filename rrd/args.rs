use clap::{crate_authors, crate_description, crate_name, crate_version};
use clap::{App, AppSettings, Arg};

/// Subcommands with configs.
#[derive(Debug)]
pub enum Args {
    Node(ConfigNode),
}

#[derive(Debug)]
pub struct ConfigNode {}

/// Parse program arguments to [`Args`][Args].
pub fn get_args() -> Args {
    let version = include_str!("./args.rs-version").trim();
    if version.split_whitespace().collect::<Vec<&str>>()[0] != crate_version!() {
        panic!(
            "Saved version missmatch, saved: {}, CARGO_PKG_VERSION: {}",
            version,
            crate_version!()
        );
    }

    let _matches = App::new(crate_name!())
        .author(crate_authors!())
        .about(crate_description!())
        .version(version)
        .settings(&[AppSettings::DeriveDisplayOrder])
        .args(&[Arg::with_name("config")
            .long("config")
            .help("Path to config file")
            .value_name("config")
            .default_value("rrd.cfg") // TODO
            .env("RRD_CONFIG")])
        .get_matches();

    Args::Node(ConfigNode {})
}
