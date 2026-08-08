# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo fmt --all -- --check                                    # format check (CI)
cargo clippy --workspace --all-targets --all-features -- -D warnings  # lint (CI)
cargo test --workspace                                        # unit tests (CI)
cargo test --workspace -- --ignored                            # Docker-gated integration tests (CI, needs testcontainers)
cargo test -p core some_test_name                              # run a single test
cargo build --release
```

CI (`.github/workflows/ci.yml`) runs format → clippy → unit tests → Docker integration tests, in that order, on PRs into `main`/`develop`.

## Architecture

`aws-net-hound` is a Cargo workspace with three crates:

- **`crates/core`** — library only, no binary entry point. Holds the Neo4j graph schema, domain types, and all testable logic. Depends on `neo4rs` (Neo4j driver), `serde`/`serde_norway`, `thiserror`, `tokio`, `tracing`.
- **`crates/audit-local`** — thin binary (local CLI variant), depends on `core`.
- **`crates/aws-deploy`** — thin binary (deployed variant), depends on `core`.

Both binaries are meant to stay thin wrappers; business logic and anything unit-testable belongs in `core` so it's shared and testable without a binary.

### Graph model

The project audits AWS network topology by modeling it as a graph in Neo4j. Per `crates/core/docs/schema.md` (authoritative model description, Cypher migrations are derived from it, not the reverse):

- **Nodes**: `ENI`, `SecurityGroup`, `NetworkACL`, `Subnet`, `VPC`, `RouteTable`, `RegulatedBoundary` (e.g. PCI is one example of a regulated boundary, not the only one).
- **Edges** split into two categories:
  - *Topology*: `HAS_SG`, `IN_SUBNET`, `PROTECTED_BY`, `USES_ROUTE_TABLE`, `ROUTES_TO`.
  - *Evaluable rules*: `ALLOWS_EGRESS`, `ALLOWS_INGRESS`, `HAS_RULE` (carries an explicit ordered integer `rule_number`, never inferred from insertion order).
- `resolved: bool` on rule edges marks references that couldn't be resolved (e.g. cross-account SG references in local-audit mode) without failing ingestion.

Work is tracked in milestone-numbered GitHub issues (`M<n>-T<n>`) against a `milestone-<n>-tasks.md` spec per milestone.

## Workspace-wide lint policy

Enforced via `[workspace.lints]` in the root `Cargo.toml` — do not bypass with local `#[allow(...)]` without justification:

- `unsafe_code = "forbid"`
- `clippy::unwrap_used = "deny"`
- `clippy::expect_used = "deny"`

`rustfmt.toml` sets `max_width = 100`.
