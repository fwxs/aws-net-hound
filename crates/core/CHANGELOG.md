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

## Milestone 1 — AWS Ingestion (closed)

Implements the concrete Neo4j `GraphWriter` and the AWS-to-graph ingestion
pipeline for a single account and region: EC2 resource collection, SG/NACL
rule mapping, topology mapping, and orchestration into a written graph
batch.

Delivered:

- EC2 client construction with region resolution and the SDK's standard
  retry policy (`crates/core/src/ingest/aws_client.rs`).
- Five paginated collectors for security groups, network ACLs, route
  tables, network interfaces, and VPC peering connections
  (`crates/core/src/ingest/collect.rs`).
- Mapping from raw AWS resources to graph nodes and edges, including SG
  and NACL rule mapping with explicit `rule_number` ordering and
  `resolved` handling for unresolvable cross-account references
  (`crates/core/src/ingest/map/`).
- The concrete Neo4j `GraphWriter` implementation
  (`crates/core/src/graph/neo4j.rs`).
- `run_full_ingest` orchestration and `IngestReport`
  (`crates/core/src/ingest/pipeline.rs`).
- Ingestion behaviour documented in `crates/core/docs/ingest.md`: scope,
  `resolved: false` semantics, the NACL ordering guarantee, retry
  configuration, and how to run against a sandbox account.

Out of scope for this milestone (tracked in later milestones):

- **Milestone 2** — the real reachability evaluator.
- **Milestone 3** — the CLI.
- **Milestone 4** — reporting.
- **A later milestone** — cross-account resolution of unresolved
  references (security-group references and VPC peering connections into
  other accounts).
