//! Shared fixture for Docker-gated integration tests: a cross-process lock
//! serializing access to the single `docker-compose.yml` Neo4j stack.
//!
//! `cargo test -- --ignored` runs each integration-test *binary*
//! (`preflight_integration`, `run_integration`, ...) as a separate OS
//! process, concurrently. All of them drive the same fixed-name compose
//! service (`audit-local-neo4j-1`), so without serialization one binary's
//! `docker compose up` can race another's `down -v`, producing "container
//! name already in use" or a mid-test "connection refused". `File::lock`
//! (std, stable since 1.89) blocks until the previous holder's guard drops,
//! giving each test exclusive use of the stack for its own up/run/down
//! cycle. Not itself a test binary — reached via `mod common;`.

#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::path::PathBuf;

/// Held for the duration of one test's exclusive use of the compose stack.
/// Unlocked automatically when dropped (end of scope, including on panic).
pub struct ComposeLock {
    _file: File,
}

/// Acquires the cross-process compose-stack lock, blocking until any other
/// integration-test binary currently holding it finishes. The lock file
/// lives alongside the crate's own directory (created if absent) so it
/// never needs cleanup tracked in version control — `docker-compose.yml`
/// already lives here, so the crate directory is guaranteed writable in CI.
pub fn lock_compose_stack() -> ComposeLock {
    let path = lock_file_path();
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .unwrap_or_else(|error| panic!("failed to open compose lock file {path:?}: {error}"));
    file.lock()
        .unwrap_or_else(|error| panic!("failed to acquire compose lock: {error}"));
    ComposeLock { _file: file }
}

fn lock_file_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".compose.lock")
}
