mod oracle;
mod schemas;

use std::path::{Path, PathBuf};

/// The workspace root, resolved from this crate's own manifest directory
/// rather than the process's current working directory, so `cargo xtask
/// ...` behaves the same regardless of where it's invoked from.
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Dispatches the requested workspace maintenance command.
///
/// # Examples
///
/// ```no_run
/// let result = main();
/// assert!(result.is_ok());
/// ```
///
/// Supported commands include `sync-oracle`, `schemas`, and `schemas --check`.
///
/// Returns an error if command parsing or execution fails.
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_command(&args)? {
        Command::SyncOracle => oracle::sync(),
        Command::Schemas { check } => schemas::generate(check),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    SyncOracle,
    Schemas { check: bool },
}

/// Parses supported xtask command-line arguments.
///
/// Recognized commands are `sync-oracle`, `schemas`, and `schemas --check`.
///
/// # Examples
///
/// ```
/// let args = vec!["schemas".to_owned(), "--check".to_owned()];
/// assert!(matches!(
///     parse_command(&args),
///     Ok(Command::Schemas { check: true })
/// ));
/// ```
///
/// # Errors
///
/// Returns an error when the arguments do not match a supported command form.
fn parse_command(args: &[String]) -> anyhow::Result<Command> {
    match args {
        [command] if command == "sync-oracle" => Ok(Command::SyncOracle),
        [command] if command == "schemas" => Ok(Command::Schemas { check: false }),
        [command, flag] if command == "schemas" && flag == "--check" => {
            Ok(Command::Schemas { check: true })
        }
        _ => anyhow::bail!(
            "invalid xtask arguments: {args:?} (expected: sync-oracle, schemas [--check])"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_supported_commands() {
        assert_eq!(
            parse_command(&args(&["sync-oracle"])).unwrap(),
            Command::SyncOracle
        );
        assert_eq!(
            parse_command(&args(&["schemas"])).unwrap(),
            Command::Schemas { check: false }
        );
        assert_eq!(
            parse_command(&args(&["schemas", "--check"])).unwrap(),
            Command::Schemas { check: true }
        );
    }

    #[test]
    fn rejects_unsupported_command_shapes() {
        for values in [
            &[][..],
            &["sync-oracle", "--check"],
            &["schemas", "--chek"],
            &["schemas", "--check", "extra"],
        ] {
            assert!(parse_command(&args(values)).is_err(), "accepted {values:?}");
        }
    }
}
