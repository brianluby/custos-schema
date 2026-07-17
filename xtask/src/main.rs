mod oracle;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sync-oracle") => oracle::sync(),
        cmd => anyhow::bail!("unknown xtask command: {cmd:?} (expected: sync-oracle)"),
    }
}
