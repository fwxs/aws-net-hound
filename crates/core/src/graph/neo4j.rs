//! [`GraphWriter`] implementation over a live Neo4j connection.
//!
//! Every upsert is a `MERGE` keyed per the doc comment on the corresponding
//! `crate::ports` record type, batched via `UNWIND` so a full ingestion pass
//! costs one round trip per [`BATCH_SIZE`] chunk instead of one per record.
//! Never `CREATE`s a node or relationship directly — see
//! `crates/core/docs/schema.md` for why idempotent re-ingestion matters.

use std::collections::HashMap;

use neo4rs::{query, BoltType, Graph};
use tracing::{debug, info};

use crate::domain::rule::{Direction, PortRange, RuleTarget};
use crate::error::GraphWriteError;
use crate::graph::model::Edge;
use crate::ports::{
    BoxFuture, EniRecord, GraphWriter, HasSgEdge, InSubnetEdge, NaclRuleBatch, NetworkAclRecord,
    ProtectedByEdge, RegulatedBoundaryRecord, RouteTableRecord, RoutesToEdge, SecurityGroupRecord,
    SgRuleBatch, SubnetRecord, UsesRouteTableEdge, VpcRecord,
};

/// Rows per `UNWIND` statement. A fixed, boring constant rather than an
/// adaptive batcher — see the M1-T5 issue's rationale.
const BATCH_SIZE: usize = 1000;

/// One `UNWIND $rows AS row` parameter row.
type Row = HashMap<String, BoltType>;

/// A [`GraphWriter`] backed by a live [`neo4rs::Graph`] connection.
pub struct Neo4jGraphWriter {
    graph: Graph,
}

impl Neo4jGraphWriter {
    /// Wraps an already-connected [`Graph`]. Callers are responsible for
    /// running `crate::migrations::run` first so the uniqueness constraints
    /// backing every `MERGE` below already exist.
    pub fn new(graph: Graph) -> Self {
        Self { graph }
    }

    async fn run_node_upsert(
        &self,
        label: &'static str,
        rows: Vec<Row>,
    ) -> Result<(), GraphWriteError> {
        let cypher = node_upsert_query(label);
        let total = rows.len();
        for chunk in chunk_rows(&rows, BATCH_SIZE) {
            debug!(label, chunk_len = chunk.len(), "running node upsert");
            self.graph
                .run(query(&cypher).param("rows", chunk.to_vec()))
                .await
                .map_err(|source| GraphWriteError::Write {
                    source: Box::new(source),
                })?;
        }
        info!(label, count = total, "upserted nodes");
        Ok(())
    }

    /// Runs an edge-upsert `UNWIND` statement that ends `RETURN count(r) AS
    /// merged`, and errors out naming `edge_type` when fewer relationships
    /// were merged than rows were sent — the signal that at least one row's
    /// endpoint(s) did not resolve to an existing node. `MATCH` + `MERGE`
    /// otherwise fails silently (zero rows matched, no Cypher error), so
    /// this count comparison is how a plain `MATCH`+`MERGE` shape (every
    /// topology edge, `ROUTES_TO_RESOLVED_UPSERT`, and the
    /// `..._SG_REF_RESOLVED_UPSERT` queries) surfaces a genuinely missing
    /// endpoint. It does **not** apply to the self-loop shapes
    /// (`ROUTES_TO_UNRESOLVED_UPSERT`, the CIDR-target `ALLOWS_*` queries,
    /// and `..._SG_REF_UNRESOLVED_UPSERT`) — those always merge onto the
    /// source node by construction and never fail this check; whether a
    /// destination legitimately doesn't exist is decided by the caller
    /// before choosing which query to run, not by this count.
    async fn run_edge_upsert(
        &self,
        edge_type: &'static str,
        cypher: &'static str,
        rows: Vec<Row>,
    ) -> Result<(), GraphWriteError> {
        let mut merged_total: usize = 0;
        for chunk in chunk_rows(&rows, BATCH_SIZE) {
            debug!(edge_type, chunk_len = chunk.len(), "running edge upsert");
            let mut stream = self
                .graph
                .execute(query(cypher).param("rows", chunk.to_vec()))
                .await
                .map_err(|source| GraphWriteError::Write {
                    source: Box::new(source),
                })?;
            let row = stream
                .next()
                .await
                .map_err(|source| GraphWriteError::Write {
                    source: Box::new(source),
                })?
                .ok_or_else(|| GraphWriteError::Write {
                    source: format!("{edge_type} upsert returned no summary row").into(),
                })?;
            let merged: i64 = row.get("merged").map_err(|source| GraphWriteError::Write {
                source: Box::new(source),
            })?;
            merged_total += merged as usize;
            if merged as usize != chunk.len() {
                return Err(GraphWriteError::Write {
                    source: format!(
                        "{edge_type} upsert: {} of {} rows had an unresolved endpoint",
                        chunk.len() - merged as usize,
                        chunk.len()
                    )
                    .into(),
                });
            }
        }
        info!(edge_type, count = merged_total, "upserted edges");
        Ok(())
    }
}

/// Splits `rows` into `batch_size`-sized (or smaller, for the final chunk)
/// slices. An empty input yields no chunks.
fn chunk_rows<T>(rows: &[T], batch_size: usize) -> impl Iterator<Item = &[T]> {
    rows.chunks(batch_size)
}

fn string_prop(value: &str) -> BoltType {
    BoltType::from(value.to_string())
}

fn opt_string_prop(value: &Option<String>) -> BoltType {
    BoltType::from(value.clone())
}

fn bool_prop(value: bool) -> BoltType {
    BoltType::from(value)
}

fn props_map(entries: Vec<(&str, BoltType)>) -> BoltType {
    BoltType::from(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect::<HashMap<String, BoltType>>(),
    )
}

// --- Node row builders -----------------------------------------------------
//
// Merge key: `id`. Every other field is set unconditionally on the merged
// node via `SET n += row.props`. Every node label shares the identical
// `MERGE (n:LABEL {id: row.id}) SET n += row.props` template, so the query
// string is built once by `node_upsert_query` rather than duplicated as a
// `const` per label.

fn node_upsert_query(label: &str) -> String {
    format!("UNWIND $rows AS row\nMERGE (n:{label} {{id: row.id}})\nSET n += row.props")
}

fn node_row(id: &str, props: Vec<(&str, BoltType)>) -> Row {
    HashMap::from([
        ("id".to_string(), string_prop(id)),
        ("props".to_string(), props_map(props)),
    ])
}

fn eni_row(record: &EniRecord) -> Row {
    node_row(
        &record.id,
        vec![
            ("account_id", string_prop(&record.account_id)),
            ("vpc_id", string_prop(&record.vpc_id)),
            ("subnet_id", string_prop(&record.subnet_id)),
            ("private_ip", string_prop(&record.private_ip)),
            ("description", opt_string_prop(&record.description)),
        ],
    )
}

fn security_group_row(record: &SecurityGroupRecord) -> Row {
    node_row(
        &record.id,
        vec![
            ("account_id", string_prop(&record.account_id)),
            ("vpc_id", string_prop(&record.vpc_id)),
            ("name", string_prop(&record.name)),
            ("description", opt_string_prop(&record.description)),
        ],
    )
}

fn network_acl_row(record: &NetworkAclRecord) -> Row {
    node_row(
        &record.id,
        vec![
            ("account_id", string_prop(&record.account_id)),
            ("vpc_id", string_prop(&record.vpc_id)),
            ("is_default", bool_prop(record.is_default)),
        ],
    )
}

fn subnet_row(record: &SubnetRecord) -> Row {
    node_row(
        &record.id,
        vec![
            ("account_id", string_prop(&record.account_id)),
            ("vpc_id", string_prop(&record.vpc_id)),
            ("cidr_block", string_prop(&record.cidr_block)),
            ("availability_zone", string_prop(&record.availability_zone)),
        ],
    )
}

fn vpc_row(record: &VpcRecord) -> Row {
    node_row(
        &record.id,
        vec![
            ("account_id", string_prop(&record.account_id)),
            ("cidr_block", string_prop(&record.cidr_block)),
        ],
    )
}

fn route_table_row(record: &RouteTableRecord) -> Row {
    node_row(
        &record.id,
        vec![
            ("account_id", string_prop(&record.account_id)),
            ("vpc_id", string_prop(&record.vpc_id)),
            ("is_main", bool_prop(record.is_main)),
        ],
    )
}

fn regulated_boundary_row(record: &RegulatedBoundaryRecord) -> Row {
    node_row(
        &record.id,
        vec![
            ("account_id", string_prop(&record.account_id)),
            ("name", string_prop(&record.name)),
            ("regime", string_prop(&record.regime)),
            ("description", opt_string_prop(&record.description)),
        ],
    )
}

// --- Topology edge row builders --------------------------------------------
//
// No properties on any of these four edge types — merge key is the endpoint
// pair itself, so an empty `MERGE (a)-[r:LABEL]->(b)` pattern (no property
// map) is already idempotent.

const HAS_SG_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:ENI {id: row.eni_id}), (b:SecurityGroup {id: row.security_group_id})
MERGE (a)-[r:HAS_SG]->(b)
RETURN count(r) AS merged";

fn has_sg_row(edge: &HasSgEdge) -> Row {
    HashMap::from([
        ("eni_id".to_string(), string_prop(&edge.eni_id)),
        (
            "security_group_id".to_string(),
            string_prop(&edge.security_group_id),
        ),
    ])
}

const IN_SUBNET_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:ENI {id: row.eni_id}), (b:Subnet {id: row.subnet_id})
MERGE (a)-[r:IN_SUBNET]->(b)
RETURN count(r) AS merged";

fn in_subnet_row(edge: &InSubnetEdge) -> Row {
    HashMap::from([
        ("eni_id".to_string(), string_prop(&edge.eni_id)),
        ("subnet_id".to_string(), string_prop(&edge.subnet_id)),
    ])
}

const PROTECTED_BY_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:Subnet {id: row.subnet_id}), (b:NetworkACL {id: row.network_acl_id})
MERGE (a)-[r:PROTECTED_BY]->(b)
RETURN count(r) AS merged";

fn protected_by_row(edge: &ProtectedByEdge) -> Row {
    HashMap::from([
        ("subnet_id".to_string(), string_prop(&edge.subnet_id)),
        (
            "network_acl_id".to_string(),
            string_prop(&edge.network_acl_id),
        ),
    ])
}

const USES_ROUTE_TABLE_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:Subnet {id: row.subnet_id}), (b:RouteTable {id: row.route_table_id})
MERGE (a)-[r:USES_ROUTE_TABLE]->(b)
RETURN count(r) AS merged";

fn uses_route_table_row(edge: &UsesRouteTableEdge) -> Row {
    HashMap::from([
        ("subnet_id".to_string(), string_prop(&edge.subnet_id)),
        (
            "route_table_id".to_string(),
            string_prop(&edge.route_table_id),
        ),
    ])
}

// --- ROUTES_TO --------------------------------------------------------------
//
// Merge key: `(route_table_id, destination_cidr)`. Two shapes depending on
// whether the route resolved to a modeled `VPC` node (`target_vpc_id` is
// `Some`) or not (`resolved: false`, no destination node) — see
// `schema.md`'s `ROUTES_TO` notes. Split into two sub-batches up front so
// each `UNWIND` uses one Cypher shape.

const ROUTES_TO_RESOLVED_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:RouteTable {id: row.route_table_id}), (b:VPC {id: row.target_vpc_id})
MERGE (a)-[r:ROUTES_TO {destination_cidr: row.destination_cidr}]->(b)
SET r.resolved = row.resolved
RETURN count(r) AS merged";

const ROUTES_TO_UNRESOLVED_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:RouteTable {id: row.route_table_id})
MERGE (a)-[r:ROUTES_TO {destination_cidr: row.destination_cidr}]->(a)
SET r.resolved = row.resolved
RETURN count(r) AS merged";

fn routes_to_resolved_row(edge: &RoutesToEdge, target_vpc_id: &str) -> Row {
    HashMap::from([
        (
            "route_table_id".to_string(),
            string_prop(&edge.route_table_id),
        ),
        (
            "destination_cidr".to_string(),
            string_prop(&edge.destination_cidr),
        ),
        ("target_vpc_id".to_string(), string_prop(target_vpc_id)),
        ("resolved".to_string(), bool_prop(edge.resolved)),
    ])
}

fn routes_to_unresolved_row(edge: &RoutesToEdge) -> Row {
    HashMap::from([
        (
            "route_table_id".to_string(),
            string_prop(&edge.route_table_id),
        ),
        (
            "destination_cidr".to_string(),
            string_prop(&edge.destination_cidr),
        ),
        ("resolved".to_string(), bool_prop(edge.resolved)),
    ])
}

// --- Evaluable rule edges ----------------------------------------------------
//
// ALLOWS_EGRESS / ALLOWS_INGRESS merge key: `security_group_id` plus every
// field that makes the rule distinct — `protocol`, `from_port`, `to_port`,
// `target_kind`, and either `cidr` or the destination security group id,
// depending on target. Two Cypher shapes since the target is mutually
// exclusive (see `schema.md`).

const ALLOWS_EGRESS_CIDR_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:SecurityGroup {id: row.security_group_id})
MERGE (a)-[r:ALLOWS_EGRESS {
    protocol: row.protocol,
    from_port: row.from_port,
    to_port: row.to_port,
    target_kind: row.target_kind,
    cidr: row.cidr
}]->(a)
SET r.resolved = row.resolved
RETURN count(r) AS merged";

// `resolved: true` rows: a plain `MATCH` on the target — if the referenced
// security group is genuinely missing (not the expected cross-account
// case), the pattern fails to bind and `run_edge_upsert`'s count check
// correctly reports it as an error.
const ALLOWS_EGRESS_SG_REF_RESOLVED_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:SecurityGroup {id: row.security_group_id})
MATCH (b:SecurityGroup {id: row.target_security_group_id})
MERGE (a)-[r:ALLOWS_EGRESS {
    protocol: row.protocol,
    from_port: row.from_port,
    to_port: row.to_port,
    target_kind: row.target_kind,
    target_security_group_id: row.target_security_group_id
}]->(b)
SET r.resolved = row.resolved
RETURN count(r) AS merged";

// `resolved: false` rows: the reference is known to be unresolvable (e.g.
// cross-account in local-audit mode), so this always self-loops on the
// source — never a `MATCH` on the target, since there is nothing to match.
const ALLOWS_EGRESS_SG_REF_UNRESOLVED_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:SecurityGroup {id: row.security_group_id})
MERGE (a)-[r:ALLOWS_EGRESS {
    protocol: row.protocol,
    from_port: row.from_port,
    to_port: row.to_port,
    target_kind: row.target_kind,
    target_security_group_id: row.target_security_group_id
}]->(a)
SET r.resolved = row.resolved
RETURN count(r) AS merged";

const ALLOWS_INGRESS_CIDR_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:SecurityGroup {id: row.security_group_id})
MERGE (a)-[r:ALLOWS_INGRESS {
    protocol: row.protocol,
    from_port: row.from_port,
    to_port: row.to_port,
    target_kind: row.target_kind,
    cidr: row.cidr
}]->(a)
SET r.resolved = row.resolved
RETURN count(r) AS merged";

// See the egress `_RESOLVED_UPSERT`'s comment — same shape, `ALLOWS_INGRESS`.
const ALLOWS_INGRESS_SG_REF_RESOLVED_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:SecurityGroup {id: row.security_group_id})
MATCH (b:SecurityGroup {id: row.target_security_group_id})
MERGE (a)-[r:ALLOWS_INGRESS {
    protocol: row.protocol,
    from_port: row.from_port,
    to_port: row.to_port,
    target_kind: row.target_kind,
    target_security_group_id: row.target_security_group_id
}]->(b)
SET r.resolved = row.resolved
RETURN count(r) AS merged";

// See the egress `_UNRESOLVED_UPSERT`'s comment — same shape, `ALLOWS_INGRESS`.
const ALLOWS_INGRESS_SG_REF_UNRESOLVED_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:SecurityGroup {id: row.security_group_id})
MERGE (a)-[r:ALLOWS_INGRESS {
    protocol: row.protocol,
    from_port: row.from_port,
    to_port: row.to_port,
    target_kind: row.target_kind,
    target_security_group_id: row.target_security_group_id
}]->(a)
SET r.resolved = row.resolved
RETURN count(r) AS merged";

fn port_range_props(port_range: Option<PortRange>) -> (BoltType, BoltType) {
    match port_range {
        Some(range) => (
            BoltType::from(i64::from(range.from_port())),
            BoltType::from(i64::from(range.to_port())),
        ),
        None => (
            BoltType::Null(neo4rs::BoltNull),
            BoltType::Null(neo4rs::BoltNull),
        ),
    }
}

fn sg_rule_cidr_row(
    security_group_id: &str,
    rule: &crate::domain::rule::SgRule,
    cidr: &str,
) -> Row {
    let (from_port, to_port) = port_range_props(rule.port_range);
    HashMap::from([
        (
            "security_group_id".to_string(),
            string_prop(security_group_id),
        ),
        ("protocol".to_string(), string_prop(&rule.protocol)),
        ("from_port".to_string(), from_port),
        ("to_port".to_string(), to_port),
        ("target_kind".to_string(), string_prop("cidr")),
        ("cidr".to_string(), string_prop(cidr)),
        ("resolved".to_string(), bool_prop(rule.resolved)),
    ])
}

fn sg_rule_sg_ref_row(
    security_group_id: &str,
    rule: &crate::domain::rule::SgRule,
    target_security_group_id: &str,
) -> Row {
    let (from_port, to_port) = port_range_props(rule.port_range);
    HashMap::from([
        (
            "security_group_id".to_string(),
            string_prop(security_group_id),
        ),
        ("protocol".to_string(), string_prop(&rule.protocol)),
        ("from_port".to_string(), from_port),
        ("to_port".to_string(), to_port),
        ("target_kind".to_string(), string_prop("security_group_ref")),
        (
            "target_security_group_id".to_string(),
            string_prop(target_security_group_id),
        ),
        ("resolved".to_string(), bool_prop(rule.resolved)),
    ])
}

/// Splits `batches` into CIDR-targeted rows and security-group-ref-targeted
/// rows, since the two share no Cypher shape (see `schema.md`'s "Evaluable
/// rules" — target is mutually exclusive). SG-ref rows are further split by
/// `rule.resolved`: a resolved reference must `MATCH` a real target node (a
/// genuinely missing target is a write error), while an unresolved
/// reference is known unresolvable and always self-loops — see the
/// `_RESOLVED_UPSERT`/`_UNRESOLVED_UPSERT` query comments.
fn split_sg_rule_rows(batches: &[SgRuleBatch<'_>]) -> (Vec<Row>, Vec<Row>, Vec<Row>) {
    let mut cidr_rows = Vec::new();
    let mut sg_ref_resolved_rows = Vec::new();
    let mut sg_ref_unresolved_rows = Vec::new();
    for batch in batches {
        for rule in batch.rules {
            match &rule.target {
                RuleTarget::Cidr { cidr } => {
                    cidr_rows.push(sg_rule_cidr_row(batch.security_group_id, rule, cidr));
                }
                RuleTarget::SecurityGroupRef { security_group_id } => {
                    let row = sg_rule_sg_ref_row(batch.security_group_id, rule, security_group_id);
                    if rule.resolved {
                        sg_ref_resolved_rows.push(row);
                    } else {
                        sg_ref_unresolved_rows.push(row);
                    }
                }
            }
        }
    }
    (cidr_rows, sg_ref_resolved_rows, sg_ref_unresolved_rows)
}

// --- HAS_RULE ---------------------------------------------------------------
//
// Self-edge on `NetworkACL`. Merge key: `network_acl_id` plus
// `rule_number` — two rules to the same ACL must never collapse into one
// even if every other field matches, since `rule_number` is the evaluation
// order key.

const HAS_RULE_UPSERT: &str = "\
UNWIND $rows AS row
MATCH (a:NetworkACL {id: row.network_acl_id})
MERGE (a)-[r:HAS_RULE {rule_number: row.rule_number}]->(a)
SET r.direction = row.direction,
    r.protocol = row.protocol,
    r.from_port = row.from_port,
    r.to_port = row.to_port,
    r.cidr = row.cidr,
    r.action = row.action
RETURN count(r) AS merged";

fn nacl_rule_row(network_acl_id: &str, rule: &crate::domain::rule::NaclRule) -> Row {
    let (from_port, to_port) = port_range_props(rule.port_range);
    let direction = match rule.direction {
        Direction::Ingress => "ingress",
        Direction::Egress => "egress",
    };
    let action = match rule.action {
        crate::domain::rule::Action::Allow => "allow",
        crate::domain::rule::Action::Deny => "deny",
    };
    HashMap::from([
        ("network_acl_id".to_string(), string_prop(network_acl_id)),
        (
            "rule_number".to_string(),
            BoltType::from(i64::from(rule.rule_number)),
        ),
        ("direction".to_string(), string_prop(direction)),
        ("protocol".to_string(), string_prop(&rule.protocol)),
        ("from_port".to_string(), from_port),
        ("to_port".to_string(), to_port),
        ("cidr".to_string(), string_prop(&rule.cidr)),
        ("action".to_string(), string_prop(action)),
    ])
}

impl GraphWriter for Neo4jGraphWriter {
    fn upsert_enis(&self, enis: &[EniRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = enis.iter().map(eni_row).collect();
        Box::pin(async move { self.run_node_upsert("ENI", rows).await })
    }

    fn upsert_security_groups(
        &self,
        security_groups: &[SecurityGroupRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = security_groups.iter().map(security_group_row).collect();
        Box::pin(async move { self.run_node_upsert("SecurityGroup", rows).await })
    }

    fn upsert_network_acls(
        &self,
        network_acls: &[NetworkAclRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = network_acls.iter().map(network_acl_row).collect();
        Box::pin(async move { self.run_node_upsert("NetworkACL", rows).await })
    }

    fn upsert_subnets(
        &self,
        subnets: &[SubnetRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = subnets.iter().map(subnet_row).collect();
        Box::pin(async move { self.run_node_upsert("Subnet", rows).await })
    }

    fn upsert_vpcs(&self, vpcs: &[VpcRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = vpcs.iter().map(vpc_row).collect();
        Box::pin(async move { self.run_node_upsert("VPC", rows).await })
    }

    fn upsert_route_tables(
        &self,
        route_tables: &[RouteTableRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = route_tables.iter().map(route_table_row).collect();
        Box::pin(async move { self.run_node_upsert("RouteTable", rows).await })
    }

    fn upsert_regulated_boundaries(
        &self,
        boundaries: &[RegulatedBoundaryRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = boundaries.iter().map(regulated_boundary_row).collect();
        Box::pin(async move { self.run_node_upsert("RegulatedBoundary", rows).await })
    }

    fn upsert_has_sg_edges(
        &self,
        edges: &[HasSgEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = edges.iter().map(has_sg_row).collect();
        Box::pin(async move { self.run_edge_upsert("HAS_SG", HAS_SG_UPSERT, rows).await })
    }

    fn upsert_in_subnet_edges(
        &self,
        edges: &[InSubnetEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = edges.iter().map(in_subnet_row).collect();
        Box::pin(async move {
            self.run_edge_upsert("IN_SUBNET", IN_SUBNET_UPSERT, rows)
                .await
        })
    }

    fn upsert_protected_by_edges(
        &self,
        edges: &[ProtectedByEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = edges.iter().map(protected_by_row).collect();
        Box::pin(async move {
            self.run_edge_upsert("PROTECTED_BY", PROTECTED_BY_UPSERT, rows)
                .await
        })
    }

    fn upsert_uses_route_table_edges(
        &self,
        edges: &[UsesRouteTableEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = edges.iter().map(uses_route_table_row).collect();
        Box::pin(async move {
            self.run_edge_upsert("USES_ROUTE_TABLE", USES_ROUTE_TABLE_UPSERT, rows)
                .await
        })
    }

    fn upsert_routes_to_edges(
        &self,
        edges: &[RoutesToEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let mut resolved_rows = Vec::new();
        let mut unresolved_rows = Vec::new();
        let mut inconsistency: Option<String> = None;
        for edge in edges {
            match (&edge.target_vpc_id, edge.resolved) {
                (Some(target_vpc_id), true) => {
                    resolved_rows.push(routes_to_resolved_row(edge, target_vpc_id));
                }
                (None, false) => unresolved_rows.push(routes_to_unresolved_row(edge)),
                (target_vpc_id, resolved) => {
                    inconsistency.get_or_insert_with(|| {
                        format!(
                            "ROUTES_TO edge for route_table_id={} destination_cidr={} is \
                             inconsistent: target_vpc_id={target_vpc_id:?} but resolved={resolved}",
                            edge.route_table_id, edge.destination_cidr
                        )
                    });
                }
            }
        }
        if let Some(source) = inconsistency {
            return Box::pin(async move {
                Err(GraphWriteError::Write {
                    source: source.into(),
                })
            });
        }
        Box::pin(async move {
            self.run_edge_upsert("ROUTES_TO", ROUTES_TO_RESOLVED_UPSERT, resolved_rows)
                .await?;
            self.run_edge_upsert("ROUTES_TO", ROUTES_TO_UNRESOLVED_UPSERT, unresolved_rows)
                .await
        })
    }

    fn upsert_allows_egress_rules(
        &self,
        batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let (cidr_rows, sg_ref_resolved_rows, sg_ref_unresolved_rows) = split_sg_rule_rows(batches);
        Box::pin(async move {
            self.run_edge_upsert("ALLOWS_EGRESS", ALLOWS_EGRESS_CIDR_UPSERT, cidr_rows)
                .await?;
            self.run_edge_upsert(
                "ALLOWS_EGRESS",
                ALLOWS_EGRESS_SG_REF_RESOLVED_UPSERT,
                sg_ref_resolved_rows,
            )
            .await?;
            self.run_edge_upsert(
                "ALLOWS_EGRESS",
                ALLOWS_EGRESS_SG_REF_UNRESOLVED_UPSERT,
                sg_ref_unresolved_rows,
            )
            .await
        })
    }

    fn upsert_allows_ingress_rules(
        &self,
        batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let (cidr_rows, sg_ref_resolved_rows, sg_ref_unresolved_rows) = split_sg_rule_rows(batches);
        Box::pin(async move {
            self.run_edge_upsert("ALLOWS_INGRESS", ALLOWS_INGRESS_CIDR_UPSERT, cidr_rows)
                .await?;
            self.run_edge_upsert(
                "ALLOWS_INGRESS",
                ALLOWS_INGRESS_SG_REF_RESOLVED_UPSERT,
                sg_ref_resolved_rows,
            )
            .await?;
            self.run_edge_upsert(
                "ALLOWS_INGRESS",
                ALLOWS_INGRESS_SG_REF_UNRESOLVED_UPSERT,
                sg_ref_unresolved_rows,
            )
            .await
        })
    }

    fn upsert_has_rules(
        &self,
        batches: &[NaclRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let rows = batches
            .iter()
            .flat_map(|batch| {
                batch
                    .rules
                    .iter()
                    .map(move |rule| nacl_rule_row(batch.network_acl_id, rule))
            })
            .collect();
        Box::pin(async move {
            self.run_edge_upsert("HAS_RULE", HAS_RULE_UPSERT, rows)
                .await
        })
    }
}

/// Egress or ingress `SgRule`s grouped by owning `SecurityGroup.id`.
type SgRulesByGroup<'a> = HashMap<&'a str, Vec<&'a crate::domain::rule::SgRule>>;
/// `NaclRule`s grouped by owning `NetworkACL.id`.
type NaclRulesByAcl<'a> = HashMap<&'a str, Vec<&'a crate::domain::rule::NaclRule>>;

/// Groups a mapping layer's flat [`Edge`] list by owning security group /
/// network ACL id, matching the shape [`GraphWriter::upsert_allows_egress_rules`],
/// [`GraphWriter::upsert_allows_ingress_rules`], and
/// [`GraphWriter::upsert_has_rules`] expect. Exposed so a caller draining a
/// `crate::graph::model::GraphBatch` doesn't have to reimplement the
/// grouping.
pub fn group_rule_edges(
    edges: &[Edge],
) -> (SgRulesByGroup<'_>, SgRulesByGroup<'_>, NaclRulesByAcl<'_>) {
    let mut egress: SgRulesByGroup<'_> = HashMap::new();
    let mut ingress: SgRulesByGroup<'_> = HashMap::new();
    let mut nacl: NaclRulesByAcl<'_> = HashMap::new();

    for edge in edges {
        match edge {
            Edge::AllowsEgress {
                security_group_id,
                rule,
            } => egress.entry(security_group_id).or_default().push(rule),
            Edge::AllowsIngress {
                security_group_id,
                rule,
            } => ingress.entry(security_group_id).or_default().push(rule),
            Edge::HasRule {
                network_acl_id,
                rule,
            } => nacl.entry(network_acl_id).or_default().push(rule),
            Edge::HasSg(_)
            | Edge::InSubnet(_)
            | Edge::ProtectedBy(_)
            | Edge::UsesRouteTable(_)
            | Edge::RoutesTo(_) => {}
        }
    }

    (egress, ingress, nacl)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::chunk_rows;

    #[test]
    fn chunk_rows_splits_at_batch_size_boundary() {
        // Arrange
        let rows: Vec<u32> = (0..2500).collect();

        // Act
        let chunks: Vec<&[u32]> = chunk_rows(&rows, 1000).collect();

        // Assert
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 1000);
        assert_eq!(chunks[1].len(), 1000);
        assert_eq!(chunks[2].len(), 500);
    }

    #[test]
    fn chunk_rows_empty_input_produces_no_statements() {
        // Arrange
        let rows: Vec<u32> = Vec::new();

        // Act
        let chunks: Vec<&[u32]> = chunk_rows(&rows, 1000).collect();

        // Assert
        assert!(chunks.is_empty());
    }
}
