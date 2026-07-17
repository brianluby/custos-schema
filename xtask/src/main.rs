mod oracle;
mod schemas;

use std::path::{Path, PathBuf};

/// The workspace root, resolved from this crate's own manifest directory
/// rather than the process's current working directory, so `cargo xtask
/// ...` behaves the same regardless of where it's invoked from.
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sync-oracle") => oracle::sync(),
        Some("schemas") => schemas::generate(args.iter().any(|a| a == "--check")),
        cmd => anyhow::bail!("unknown xtask command: {cmd:?} (expected: sync-oracle, schemas)"),
    }
}
