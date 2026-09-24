//! Testable core of the `audit-local` binary: CLI definition, dispatch,
//! and the [`Outcome`] exit-code contract. `main.rs` only parses,
//! initializes tracing, dispatches here, and maps the result to a process
//! exit code.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

pub mod aws_error;
pub mod config;
pub mod preflight;
pub mod run;

/// `audit-local` command-line interface.
#[derive(Debug, Parser)]
#[command(name = "audit-local", about = "Local AWS network topology auditor")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands. Kept to exactly two: a full audit run and an environment
/// preflight check.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Run the full audit against the given config.
    Run {
        /// Path to the audit configuration file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Check that the local environment (Docker, AWS credentials, etc.) is
    /// ready to run an audit.
    Preflight,
}

/// Outcome of a completed `audit-local` run.
///
/// Maps to a process exit code:
/// - [`Outcome::Clean`] -> `0`: the run completed and found no reachable
///   path into the boundary.
/// - [`Outcome::FindingsPresent`] -> `2`: the run completed and there is
///   something for the auditor to look at.
///
/// An `Err` returned from [`dispatch`] maps to exit code `1` (operational
/// failure) and is handled by the binary, not represented here.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The run completed and found no reachable path into the boundary.
    Clean,
    /// The run completed and found findings the auditor should review.
    FindingsPresent {
        /// Count of confirmed reachable paths.
        reachable: usize,
        /// Count of paths that could not be conclusively resolved.
        indeterminate: usize,
    },
}

impl Outcome {
    /// The process exit code for this outcome.
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Clean => 0,
            Outcome::FindingsPresent { .. } => 2,
        }
    }
}

/// Dispatch a parsed [`Command`] to its implementation.
pub async fn dispatch(command: Command) -> anyhow::Result<Outcome> {
    match command {
        Command::Run { config } => {
            let raw = config::Config::from_path(&config).context("failed to read config file")?;
            let validated = raw.validate().context("failed to validate config")?;
            run::run(validated).await
        }
        Command::Preflight => {
            preflight::run().await?;
            Ok(Outcome::Clean)
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn cli_parse_run_without_config_returns_error() {
        let args = ["audit-local", "run"];

        let result = Cli::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn cli_parse_run_with_config_returns_run_command() {
        let args = ["audit-local", "run", "--config", "audit.yaml"];

        let result = Cli::try_parse_from(args);

        let Ok(cli) = result else {
            panic!("expected successful parse, got {result:?}");
        };
        assert_eq!(
            cli.command,
            Command::Run {
                config: PathBuf::from("audit.yaml"),
            }
        );
    }

    #[test]
    fn cli_parse_unknown_subcommand_returns_error() {
        let args = ["audit-local", "bogus"];

        let result = Cli::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn outcome_clean_maps_to_exit_code_zero() {
        let outcome = Outcome::Clean;

        let code = outcome.exit_code();

        assert_eq!(code, 0);
    }

    #[test]
    fn outcome_findings_present_maps_to_exit_code_two() {
        let outcome = Outcome::FindingsPresent {
            reachable: 1,
            indeterminate: 0,
        };

        let code = outcome.exit_code();

        assert_eq!(code, 2);
    }

    #[test]
    fn cli_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }
}
