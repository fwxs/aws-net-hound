//! Docker-gated integration tests for the preflight check, matching CI job
//! `integration-tests` (`cargo test --workspace -- --ignored`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

mod common;

const COMPOSE_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// `preflight::run()` shells out to `docker compose`, which reads
/// `NEO4J_PASSWORD` from this test process's environment — there is no
/// other way to inject it into that child process, since `preflight`
/// itself never touches the variable directly. Panics with a clear message
/// rather than letting the compose interpolation error stand in for a
/// missing test precondition.
fn test_password() -> String {
    std::env::var("NEO4J_PASSWORD").unwrap_or_else(|_| {
        panic!(
            "run this test with NEO4J_PASSWORD set, e.g.:\n  \
             NEO4J_PASSWORD=test cargo test -p audit-local --test preflight_integration -- --ignored"
        )
    })
}

fn compose_down(password: &str) {
    let _ = Command::new("docker")
        .args(["compose", "down", "-v"])
        .current_dir(COMPOSE_DIR)
        .env("NEO4J_PASSWORD", password)
        .output();
}

/// Ensures the stack is torn down even if the test panics or the assertion
/// fails, so a failed run doesn't leave a container behind for the next one.
struct ComposeGuard {
    password: String,
}

impl Drop for ComposeGuard {
    fn drop(&mut self) {
        compose_down(&self.password);
    }
}

#[tokio::test]
#[ignore]
async fn preflight_waits_for_healthy_container_then_returns_ok() {
    let _lock = common::lock_compose_stack();
    let password = test_password();
    let _guard = ComposeGuard {
        password: password.clone(),
    };
    compose_down(&password);

    let up = Command::new("docker")
        .args(["compose", "up", "-d"])
        .current_dir(COMPOSE_DIR)
        .env("NEO4J_PASSWORD", &password)
        .output()
        .expect("failed to spawn docker compose up");
    assert!(
        up.status.success(),
        "docker compose up failed: {}",
        String::from_utf8_lossy(&up.stderr)
    );

    let result = audit_local::preflight::run().await;

    assert!(result.is_ok(), "expected Ok, got {result:?}");
}

#[tokio::test]
#[ignore]
async fn preflight_missing_service_returns_absent_error() {
    let _lock = common::lock_compose_stack();
    let password = test_password();
    let _guard = ComposeGuard {
        password: password.clone(),
    };
    compose_down(&password);

    let result = audit_local::preflight::run().await;

    assert!(matches!(
        result,
        Err(audit_local::preflight::PreflightError::ServiceAbsent)
    ));
}
