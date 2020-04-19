use std::fs;

use git2::Repository;

fn main() {
    generate_args_gitrev();
}

fn generate_args_gitrev() {
    let gitrev = load_git_rev();
    let data = format!("{} (git rev: {})", env!("CARGO_PKG_VERSION"), gitrev);
    fs::write("./rrd/args.rs-version", data).expect("Failed to create gitrev file");
}

fn load_git_rev() -> String {
    let repo = Repository::open("./").expect("Failed to open git repository");

    let mut rev = repo
        .head()
        .expect("Failed get HEAD")
        .target()
        .expect("Failed to get OID")
        .as_bytes()
        .iter()
        .take(4)
        .fold(String::with_capacity(8), |s, b| s + &format!("{:02x}", b));
    rev.truncate(7);

    let mut status_options = git2::StatusOptions::new();
    status_options.include_ignored(false);
    let statuses = repo
        .statuses(Some(&mut status_options))
        .expect("Failed to get statuses");

    if statuses.is_empty() {
        rev
    } else {
        format!("{}-modified", rev)
    }
}
