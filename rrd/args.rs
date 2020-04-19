use std::fmt;

use clap::{crate_authors, crate_description, crate_name, crate_version};
use clap::{App, AppSettings, Arg, ArgMatches};

/// Args struct. We would able have just function `get_args`, but we need store
/// Strings somewhere which was used for creating `clap::App` throught `&str`.
pub struct Args<'a, 'b> {
    app: App<'a, 'b>,
}

impl fmt::Debug for Args<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Args").finish()
    }
}

impl Default for Args<'_, '_> {
    fn default() -> Self {
        let app = App::new(crate_name!())
            .author(crate_authors!())
            .about(crate_description!())
            .version(crate_version!()) // TODO: add git revision
            .settings(&[AppSettings::DeriveDisplayOrder])
            .args(&[Arg::with_name("config")
                .long("config")
                .help("Path to config file")
                .value_name("config")
                .default_value("rrd.cfg") // TODO
                .env("RRD_CONFIG")]);
        Args { app }
    }
}

impl<'a> Args<'a, '_> {
    pub fn get_matches(self) -> ArgMatches<'a> {
        self.app.get_matches()
    }
}
