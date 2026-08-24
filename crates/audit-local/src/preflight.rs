//! Environment preflight: verify Docker is available and the `neo4j`
//! compose service is healthy before anything downstream tries to open a
//! Bolt connection.
//!
//! Without this, a cold or missing Docker environment surfaces as a Bolt
//! connection error deep inside the migration runner, phrased in the
//! driver's vocabulary rather than the operator's. This module gives that
//! failure a name and, when the service is merely starting, waits on the
//! real container healthcheck instead of guessing with a fixed sleep.

use std::time::Duration;

use tokio::process::Command;
use tokio::time::Instant;
use tracing::info;

/// Poll interval while waiting for the `neo4j` service to become healthy.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Total time budget for the wait before giving up. Comfortably above the
/// compose healthcheck's `start_period` (120s, see docker-compose.yml) so
/// a container that takes nearly the full start period to warm up still
/// gets at least one real healthcheck attempt inside our own timeout.
const POLL_TIMEOUT: Duration = Duration::from_secs(180);

/// Compose format template producing one `service|health|state` line per
/// service. Avoids depending on `serde_json` to parse `--format json`.
const PS_FORMAT: &str = "{{.Service}}|{{.Health}}|{{.State}}";

/// Health of the `neo4j` compose service, as reported by `docker compose
/// ps`. Not a `bool` + message: `Starting` and `Unhealthy` both mean "not
/// ready yet" but are distinguishable for diagnostics, and `Absent` means
/// the stack was never brought up at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceHealth {
    Healthy,
    Starting,
    Unhealthy,
    Absent,
}

/// Errors from the preflight check.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PreflightError {
    #[error(
        "Docker is not available ({reason}). Start Docker Desktop (or the Docker daemon) and retry."
    )]
    DockerUnavailable { reason: String },

    #[error(
        "`docker compose ps` failed: {stderr}. If this mentions NEO4J_PASSWORD, set it (see .env.example) and retry."
    )]
    ComposePsFailed { stderr: String },

    #[error("unrecognized `docker compose ps` output line: {line:?}")]
    UnexpectedOutput { line: String },

    #[error(
        "neo4j service is not up; run `docker compose up -d` in crates/audit-local/ and retry"
    )]
    ServiceAbsent,

    #[error("neo4j did not become healthy within {waited:?} (last state: {last_state:?})")]
    NotHealthy {
        waited: Duration,
        last_state: ServiceHealth,
    },
}

/// Parse `docker compose ps --format "{{.Service}}|{{.Health}}|{{.State}}"`
/// stdout for the `neo4j` service's health. Pure and Docker-free so it can
/// be unit-tested against captured output.
fn health_from_compose_ps(stdout: &str) -> Result<ServiceHealth, PreflightError> {
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split('|');
        let (Some(service), Some(health)) = (fields.next(), fields.next()) else {
            return Err(PreflightError::UnexpectedOutput {
                line: line.to_string(),
            });
        };

        if service != "neo4j" {
            continue;
        }

        return match health.to_ascii_lowercase().as_str() {
            "healthy" => Ok(ServiceHealth::Healthy),
            "starting" => Ok(ServiceHealth::Starting),
            "unhealthy" => Ok(ServiceHealth::Unhealthy),
            _ => Err(PreflightError::UnexpectedOutput {
                line: line.to_string(),
            }),
        };
    }

    Ok(ServiceHealth::Absent)
}

/// Verify the Docker CLI exists and the daemon answers.
async fn check_docker_available() -> Result<(), PreflightError> {
    let output = Command::new("docker")
        .args(["compose", "version"])
        .output()
        .await
        .map_err(|source| PreflightError::DockerUnavailable {
            reason: source.to_string(),
        })?;

    if !output.status.success() {
        return Err(PreflightError::DockerUnavailable {
            reason: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    Ok(())
}

/// Run `docker compose ps` in this crate's directory and return its
/// stdout, or a [`PreflightError::ComposePsFailed`] with the captured
/// stderr (e.g. a missing `NEO4J_PASSWORD` interpolation error).
async fn compose_ps() -> Result<String, PreflightError> {
    let output = Command::new("docker")
        .args(["compose", "ps", "--format", PS_FORMAT])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .await
        .map_err(|source| PreflightError::DockerUnavailable {
            reason: source.to_string(),
        })?;

    if !output.status.success() {
        return Err(PreflightError::ComposePsFailed {
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Poll `docker compose ps` until the `neo4j` service reports healthy, or
/// give up after [`POLL_TIMEOUT`]. Never runs `docker compose up` itself.
async fn wait_for_healthy() -> Result<(), PreflightError> {
    let start = Instant::now();

    loop {
        let health = health_from_compose_ps(&compose_ps().await?)?;

        match health {
            ServiceHealth::Healthy => return Ok(()),
            ServiceHealth::Absent => return Err(PreflightError::ServiceAbsent),
            ServiceHealth::Starting | ServiceHealth::Unhealthy => {
                let waited = start.elapsed();
                if waited >= POLL_TIMEOUT {
                    return Err(PreflightError::NotHealthy {
                        waited,
                        last_state: health,
                    });
                }
                info!(elapsed = ?waited, state = ?health, "waiting for neo4j to become healthy");
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }
}

/// Run the full preflight check: Docker available, then `neo4j` healthy.
/// On success, prints the Bolt URI and Neo4j Browser URL to stdout.
pub async fn run() -> Result<(), PreflightError> {
    check_docker_available().await?;
    wait_for_healthy().await?;

    println!("neo4j is healthy");
    println!("Bolt URI: bolt://127.0.0.1:7687");
    println!("Neo4j Browser: http://127.0.0.1:7474");

    Ok(())
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn health_from_compose_ps_healthy_service_returns_healthy() {
        let stdout = "neo4j|healthy|running\n";

        let result = health_from_compose_ps(stdout);

        assert_eq!(
            result.unwrap_or_else(|e| panic!("{e}")),
            ServiceHealth::Healthy
        );
    }

    #[test]
    fn health_from_compose_ps_starting_service_returns_starting() {
        let stdout = "neo4j|starting|running\n";

        let result = health_from_compose_ps(stdout);

        assert_eq!(
            result.unwrap_or_else(|e| panic!("{e}")),
            ServiceHealth::Starting
        );
    }

    #[test]
    fn health_from_compose_ps_unhealthy_service_returns_unhealthy() {
        let stdout = "neo4j|unhealthy|running\n";

        let result = health_from_compose_ps(stdout);

        assert_eq!(
            result.unwrap_or_else(|e| panic!("{e}")),
            ServiceHealth::Unhealthy
        );
    }

    #[test]
    fn health_from_compose_ps_empty_output_returns_absent() {
        let stdout = "";

        let result = health_from_compose_ps(stdout);

        assert_eq!(
            result.unwrap_or_else(|e| panic!("{e}")),
            ServiceHealth::Absent
        );
    }

    #[test]
    fn health_from_compose_ps_malformed_line_returns_unexpected_output_error() {
        let stdout = "neo4j|???|running\n";

        let result = health_from_compose_ps(stdout);

        assert!(matches!(
            result,
            Err(PreflightError::UnexpectedOutput { .. })
        ));
    }
}
