# Changelog

## Milestone 0 — Graph Schema & Core Contracts (closed)

Established the Neo4j graph schema, Cypher migrations, domain types, and
core trait contracts for `aws-net-hound`. No ingestion, evaluation, CLI,
or reporting code — this milestone is the shared foundation those build on.

Delivered:

- Graph schema documented in `crates/core/docs/schema.md`: seven node
  types, topology edges, and evaluable-rule edges.
- Cypher migrations (`migrations/0001_constraints.cypher`,
  `migrations/0002_indexes.cypher`) and an idempotent migration runner
  (`crates/core/src/migrations.rs`).
- Domain types for rules and findings (`crates/core/src/domain/`).
- Core port traits — `GraphWriter`, `Resolver`, `Evaluator`
  (`crates/core/src/ports.rs`) — with contract tests via mocks.

Out of scope for this milestone (tracked in later milestones):

- **Milestone 1** — the concrete Neo4j `GraphWriter` implementation and
  real AWS resource ingestion.
- **Milestone 2** — the real reachability evaluator.
- **Milestone 3** — the CLI.
- **Milestone 4** — reporting.
