# aws-net-hound

Audit AWS network topology for reachability into a regulated boundary
(PCI-DSS is one example; HIPAA, SOC 2 or an internal segmentation policy
are others).

`aws-net-hound` reads your VPC networking from AWS, models it as a graph in
Neo4j, and evaluates security group and network ACL rules to answer one
question: **which sources can reach the regulated boundary, and which paths
could not be evaluated?**

## How it works

1. **Ingest** — reads ENIs, security groups, network ACLs, route tables and
   VPC peering connections through the EC2 `Describe*` APIs (paginated, one
   account and one region per run) and writes them to Neo4j.
2. **Model** — nodes are `ENI`, `SecurityGroup`, `NetworkACL`, `Subnet`,
   `VPC`, `RouteTable` and `RegulatedBoundary`. Edges are split into topology
   (`HAS_SG`, `IN_SUBNET`, `PROTECTED_BY`, `USES_ROUTE_TABLE`, `ROUTES_TO`)
   and evaluable rules (`ALLOWS_EGRESS`, `ALLOWS_INGRESS`, `HAS_RULE`).
3. **Evaluate** — each candidate path is checked layer by layer: SG egress,
   NACL egress, NACL ingress, SG ingress. Security groups are an unordered
   union of allow rules; NACLs are ordered first-match with explicit denies.
4. **Report** — a plain-text summary on stdout.

### Three verdicts, not two

Every path ends as `Reachable`, `NotReachable` or `Indeterminate`.
Indeterminate means a rule references something the tool could not resolve
(typically a cross-account security group in local-audit mode). It is
reported separately and never folded into "not reachable": *indeterminate
does not mean safe*.

## Workspace

| Crate | Role |
|---|---|
| [`crates/core`](crates/core) | Library. Graph schema, domain types, ingestion, evaluation, migrations. All testable logic lives here. |
| [`crates/audit-local`](crates/audit-local) | Binary. Local CLI backed by a Docker Compose Neo4j. |
| [`crates/aws-deploy`](crates/aws-deploy) | Binary. Deployed variant; currently an empty stub. |

Both binaries are thin wrappers around `core`.

## Prerequisites

- Rust (2021 edition) with `cmake` and a C toolchain — the AWS SDK builds
  `aws-lc-sys` from source.
- Docker with the Compose plugin, for the local Neo4j.
- AWS credentials for the account to audit, via the standard provider chain.
  Read-only EC2 `Describe*` access plus `sts:GetCallerIdentity` is enough.

## Quick start (`audit-local`)

```bash
# 1. Start Neo4j (ephemeral by default: `docker compose down` discards the graph)
cd crates/audit-local
cp .env.example .env            # then set NEO4J_PASSWORD to something real
docker compose up -d
cd ../..

# 2. Configure the audit
cp crates/audit-local/config.example.yaml audit.yaml   # edit region, profile, boundary

# 3. Check the environment, then run
export NEO4J_PASSWORD=...       # same value as in .env
cargo run -p audit-local -- preflight
cargo run -p audit-local -- run --config audit.yaml
```

### Configuration

See [`config.example.yaml`](crates/audit-local/config.example.yaml) for the
full, commented schema. `boundary` needs at least one of `vpc_ids`, `cidrs`
or `tags`. The Neo4j password is never stored in the config file; it is read
from `NEO4J_PASSWORD`.

Currently only `vpc_ids` selects the boundary; `cidrs` and `tags` are
accepted but logged as not yet matched. `output_path` is reserved for the
report format planned for Milestone 4.

### Output and exit codes

The run summary is the only thing written to **stdout**; all logging goes to
**stderr**, so redirecting stdout gives a clean report:

```bash
audit-local run --config audit.yaml > report.txt 2> run.log
```

The summary lists reachable, indeterminate and total-evaluated counts, one
line of path evidence per reachable finding, the unresolved layer for each
indeterminate finding, and a Neo4j Browser URL with a ready-to-paste Cypher
query. Listings are capped at 25 per section.

| Exit code | Meaning |
|---|---|
| `0` | Run completed, no reachable or indeterminate paths. |
| `1` | Operational failure (config, Docker, AWS or Neo4j error). |
| `2` | Run completed with findings to review. Indeterminate-only counts too. |

Set `RUST_LOG` to change log verbosity (default `info`).

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace                 # unit tests
cargo test --workspace -- --ignored    # Docker-gated integration tests (testcontainers)
cargo build --release
```

CI runs these in that order on pull requests into `main` and `develop`.
Workspace lints forbid `unsafe` and deny `unwrap`/`expect`.

## Documentation

- [`crates/core/docs/schema.md`](crates/core/docs/schema.md) — authoritative graph model; Cypher migrations derive from it.
- [`crates/core/docs/ingest.md`](crates/core/docs/ingest.md) — ingestion scope and guarantees.
- [`crates/core/CHANGELOG.md`](crates/core/CHANGELOG.md) — `core` changes.

## License

GPL-3.0. See [LICENSE](LICENSE).
