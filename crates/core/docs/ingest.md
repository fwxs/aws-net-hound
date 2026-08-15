# Ingestion

How `aws-net-hound` populates the graph described in `schema.md` from a
real AWS account, and the guarantees that ingestion does — and does not —
make.

## Scope

Milestone 1 ingestion covers exactly one account and one region per run,
authenticated via the standard AWS credential provider chain (environment
variables, a named profile, or an instance/container role). There is no
`AssumeRole` support, no AWS Organizations traversal, and no multi-region
fan-out: to ingest a second account or region, run ingestion again with
different credentials and a different `IngestConfig`.

Region resolution is independent of credential resolution and follows its
own explicit priority order — `IngestConfig.region`, then the `AWS_REGION`
environment variable, then `AWS_DEFAULT_REGION`, then the active AWS
profile's `region` setting. EC2 instance metadata (IMDS) is deliberately
never consulted for region: an audit's region must come from an explicit,
auditable source, not wherever the process happens to run. If none of
these resolve a region, ingestion fails fast rather than falling back to a
compiled-in default.

Cross-account resolution of security-group references and VPC peering
connections is out of scope for this milestone (see "Not in scope"
below) — those references are still ingested, just marked unresolved, as
described next.

## What `resolved: false` means

A cross-account security-group reference (on an `ALLOWS_EGRESS` or
`ALLOWS_INGRESS` edge) or a VPC peering connection into another account's
VPC (on a `ROUTES_TO` edge) cannot be dereferenced in single-account,
local-audit mode. Rather than dropping it, ingestion writes the edge with
`resolved: false`. The edge is present and queryable — it is not omitted,
and ingestion does not fail because of it.

Read `resolved: false` as **indeterminate**, not **denied**. A downstream
evaluator (Milestone 2) must treat it as "traffic may or may not be
permitted here" and surface that uncertainty, never silently exclude an
unresolved reference from a reachability result or treat its absence of
resolution as a deny. See `schema.md`'s "Cross-cutting notes" section for
the underlying schema guarantee this implements.

List everything unresolved in a given graph:

```cypher
MATCH (a)-[r]->(b)
WHERE r.resolved = false
RETURN type(r) AS edge_type, a.id AS from_id, b.id AS to_id, r
```

This covers all three edge types that carry `resolved`: `ALLOWS_EGRESS`,
`ALLOWS_INGRESS`, and `ROUTES_TO`. Only the first two currently have a
`resolved` index (`migrations/0002_indexes.cypher`), so the `ROUTES_TO`
portion of this query is an unindexed scan — fine at current graph sizes,
worth revisiting if it becomes a bottleneck on a very large account.

## NACL rule ordering

`HAS_RULE.rule_number` is stored as an integer property, and ingestion
sorts NACL rules by it explicitly before writing. The AWS
`DescribeNetworkAcls` response order is never relied upon as the
evaluation order. See `schema.md`'s `HAS_RULE` properties table and
"Cross-cutting notes" section for the full guarantee this satisfies —
first match by ascending `rule_number` wins, and any code that evaluates
NACL rules must sort explicitly on this field rather than trusting
insertion or list order.

## Retry behaviour

The five paginated `Describe*` collectors this milestone runs use the AWS
SDK's standard retry policy (`RetryConfig::standard()`), configured for a
maximum of 8 attempts — including the first — per API call, with a
20-second per-attempt timeout and deliberately no overall operation
timeout (a total budget shorter than 8 attempts' worth of backoff would
silently cut retries short before they're exhausted). The SDK's built-in
exponential backoff with jitter already classifies `RequestLimitExceeded`
and other throttling responses as retryable; there is no hand-written
backoff loop in this codebase. See
`crates/core/src/ingest/aws_client.rs`.

## Not in scope

- **Reachability evaluation** (Milestone 2) — ingestion writes the graph;
  it does not answer "can X reach Y."
- **CLI** (Milestone 3) — ingestion is invoked programmatically
  (`run_full_ingest`) in this milestone; there is no command-line entry
  point yet.
- **Reporting / `PCIBoundary` classification** (Milestone 4).
- **Cross-account resolution** (a later milestone) — unresolved
  cross-account references are recorded (see above) but never
  dereferenced.

## Running against a sandbox account

Ingestion is a library call, not a CLI command, in this milestone:

```rust
let config = IngestConfig {
    region: Some("us-east-1".to_string()), // placeholder — your sandbox region
    neo4j_uri: Some("bolt://localhost:7687".to_string()),
};
let report = run_full_ingest(&config, &writer).await?;
```

Credentials are picked up from the standard AWS credential provider chain
— set `AWS_PROFILE`, or the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
/ `AWS_SESSION_TOKEN` triplet, in the environment before running. Nothing
in `IngestConfig` accepts a credential directly.

Point `neo4j_uri` at a disposable sandbox Neo4j instance (for example a
local `docker run neo4j:5`) — never a shared or production instance, since
ingestion writes real account topology.

This calls five EC2 APIs, all read-only: `DescribeSecurityGroups`,
`DescribeNetworkAcls`, `DescribeRouteTables`, `DescribeNetworkInterfaces`,
and `DescribeVpcPeeringConnections`. No AWS resource is created, modified,
or deleted. Use an IAM sandbox principal scoped to only these read-only
EC2 describe permissions, and confirm the account is one you're prepared
to have topology data extracted from before running.

A successful run returns an `IngestReport` with per-resource-kind counts,
the number of unresolved references written, the run's wall-clock
duration, and any non-fatal per-resource mapping warnings — a single
malformed resource does not fail the whole run. See `run_full_ingest`'s
doc comment in `crates/core/src/ingest/pipeline.rs` for the exact
fatal/non-fatal distinction.
