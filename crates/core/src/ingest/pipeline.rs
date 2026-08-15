//! Orchestrates the full Milestone 1 ingestion pipeline: build the AWS
//! client, run the five collectors concurrently, map the results into a
//! graph batch, write it, and report what happened.
//!
//! [`run_full_ingest`] is the one entry point Milestone 3's CLI needs from
//! this crate's `ingest` module.

use std::collections::BTreeMap;
use std::time::Instant;

use tracing::{info, warn};

use crate::error::{IngestError, MappingError};
use crate::graph::model::{Edge, GraphBatch};
use crate::ports::{GraphWriter, NaclRuleBatch, SgRuleBatch};

use super::aws_client::{build_sdk_config, resolve_account_id};
use super::collect::{
    collect_network_acls, collect_network_interfaces, collect_route_tables,
    collect_security_groups, collect_vpc_peering_connections,
};
use super::map::topology::build_graph_batch;
use super::IngestConfig;

/// The kind of AWS resource an [`IngestReport`] count refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ResourceKind {
    Eni,
    SecurityGroup,
    NetworkAcl,
    RouteTable,
    VpcPeeringConnection,
}

/// One resource that failed to map and was excluded from the run's graph
/// batch. The run continues — see [`run_full_ingest`]'s doc comment for why
/// this is non-fatal while a graph write failure is not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IngestWarning {
    pub resource_id: String,
    /// The field path within the SDK type that failed to map, e.g.
    /// `"port_range"` — see [`MappingError::InvalidField`].
    pub field: &'static str,
    /// Human-readable reason the field could not be mapped.
    pub reason: String,
}

impl From<MappingError> for IngestWarning {
    fn from(error: MappingError) -> Self {
        let MappingError::InvalidField {
            resource_id,
            field,
            reason,
        } = error;
        IngestWarning {
            resource_id,
            field,
            reason,
        }
    }
}

/// The outcome of one [`run_full_ingest`] call.
///
/// An operator must be able to tell a clean, empty account apart from a
/// partially failed ingestion without a debugger: `counts` and
/// `unresolved_references` make that legible from the report alone, not
/// just from logs.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct IngestReport {
    /// Number of each resource kind actually written to the graph — after
    /// excluding anything recorded in `non_fatal`.
    pub counts: BTreeMap<ResourceKind, usize>,
    /// Total count of `resolved: false` rule/route edges in the written
    /// batch — e.g. cross-account security-group references local-audit
    /// mode cannot dereference. Zero here on a non-empty graph means every
    /// reference resolved; a large count on the same graph means something
    /// very different, and both are visible without a debugger.
    pub unresolved_references: usize,
    /// Wall-clock time the run took, start to finish, in seconds.
    pub duration_secs: f64,
    /// Resources that failed to map and were excluded, without aborting
    /// the run. See [`run_full_ingest`]'s doc comment.
    pub non_fatal: Vec<IngestWarning>,
}

/// Runs the full Milestone 1 ingestion pipeline: builds the AWS client,
/// resolves the calling account id, runs the five EC2 collectors
/// concurrently, maps the results into a graph batch, writes it via `W`,
/// and returns a report of what was written.
///
/// # Non-fatal vs. fatal
///
/// A single resource that fails to map (a required field missing or
/// malformed) is recorded as an [`IngestWarning`] and excluded from the
/// batch; the run continues. Failing to build the client, resolve the
/// account id, exhausting a collector's retries, or a graph write failing
/// are all fatal and return `Err` — silently continuing past any of those
/// would produce a partial graph indistinguishable from a clean, empty
/// account, which is exactly the false-negative failure mode this pipeline
/// exists to prevent.
///
/// Generic over [`GraphWriter`] rather than `Box<dyn GraphWriter>` so the
/// whole pipeline can be driven end to end by an in-memory mock, with no
/// database required.
pub async fn run_full_ingest<W: GraphWriter>(
    config: &IngestConfig,
    writer: &W,
) -> Result<IngestReport, IngestError> {
    info!(region = ?config.region, "starting ingest");

    let sdk_config = build_sdk_config(config).await?;
    let account_id = resolve_account_id(&sdk_config).await?;
    let client = aws_sdk_ec2::Client::new(&sdk_config);

    run_full_ingest_with_client(&client, &account_id, writer).await
}

/// Does the actual collection, mapping, and write once the EC2 client and
/// account id are already in hand. Split out from [`run_full_ingest`] so
/// `tests/ingest_pipeline.rs` and `tests/ingest_end_to_end.rs` can each
/// drive the pipeline against an `aws-smithy-mocks` client and a fixed
/// account id directly — the latter needs this seam too since it pairs
/// mocked AWS responses with a real Neo4j, so the split can't be
/// crate-private — instead of depending on `aws_config`'s provider chain or
/// a real STS call. Mirrors the
/// [`super::aws_client::build_ec2_client`]/`build_sdk_config_from_sources`
/// split.
pub async fn run_full_ingest_with_client<W: GraphWriter>(
    client: &aws_sdk_ec2::Client,
    account_id: &str,
    writer: &W,
) -> Result<IngestReport, IngestError> {
    let start = Instant::now();

    let (security_groups, network_acls, route_tables, network_interfaces, vpc_peering_connections) =
        tokio::try_join!(
            collect_security_groups(client),
            collect_network_acls(client),
            collect_route_tables(client),
            collect_network_interfaces(client),
            collect_vpc_peering_connections(client),
        )?;

    info!(
        security_groups = security_groups.len(),
        network_acls = network_acls.len(),
        route_tables = route_tables.len(),
        network_interfaces = network_interfaces.len(),
        vpc_peering_connections = vpc_peering_connections.len(),
        "collected raw AWS resources"
    );

    let mut node_mapping_errors = Vec::new();
    let batch = build_graph_batch(
        account_id,
        &security_groups,
        &network_acls,
        &route_tables,
        &network_interfaces,
        &vpc_peering_connections,
        &mut node_mapping_errors,
    )
    .map_err(|source| IngestError::Mapping { source })?;

    let warnings: Vec<IngestWarning> = node_mapping_errors.into_iter().map(Into::into).collect();
    for warning in &warnings {
        warn!(
            resource_id = %warning.resource_id,
            field = warning.field,
            reason = %warning.reason,
            "resource excluded from graph batch: failed to map"
        );
    }

    let unresolved_references = count_unresolved(&batch);

    write_batch(writer, &batch)
        .await
        .map_err(|source| IngestError::Write { source })?;

    let mut counts = BTreeMap::new();
    counts.insert(ResourceKind::Eni, batch.enis.len());
    counts.insert(ResourceKind::SecurityGroup, batch.security_groups.len());
    counts.insert(ResourceKind::NetworkAcl, batch.network_acls.len());
    counts.insert(ResourceKind::RouteTable, batch.route_tables.len());
    counts.insert(
        ResourceKind::VpcPeeringConnection,
        vpc_peering_connections.len(),
    );

    let duration_secs = start.elapsed().as_secs_f64();
    info!(
        ?counts,
        unresolved_references,
        warnings = warnings.len(),
        duration_secs,
        "ingest complete"
    );

    Ok(IngestReport {
        counts,
        unresolved_references,
        duration_secs,
        non_fatal: warnings,
    })
}

fn count_unresolved(batch: &GraphBatch) -> usize {
    batch
        .edges
        .iter()
        .filter(|edge| match edge {
            Edge::RoutesTo(edge) => !edge.resolved,
            Edge::AllowsIngress { rule, .. } | Edge::AllowsEgress { rule, .. } => !rule.resolved,
            Edge::HasSg(_)
            | Edge::InSubnet(_)
            | Edge::ProtectedBy(_)
            | Edge::UsesRouteTable(_)
            | Edge::HasRule { .. } => false,
        })
        .count()
}

/// Groups `(key, value)` pairs by key, preserving each key's values in
/// encounter order. Shared by [`write_batch`]'s three rule-batch groupings
/// (ingress, egress, NACL) so a future fourth kind, or a fix to the
/// grouping logic itself, only needs editing in one place.
fn group_by<'a, V: Clone + 'a>(
    pairs: impl Iterator<Item = (&'a str, &'a V)>,
) -> BTreeMap<&'a str, Vec<V>> {
    let mut grouped: BTreeMap<&str, Vec<V>> = BTreeMap::new();
    for (key, value) in pairs {
        grouped.entry(key).or_default().push(value.clone());
    }
    grouped
}

/// Writes every node and edge in `batch` via `writer`. `edge.clone()`/
/// `rule.clone()` throughout: `GraphWriter`'s upsert methods need owned,
/// regrouped-by-key `Vec`s (e.g. one `SgRuleBatch` per security group), but
/// `batch.edges` is a single flat `Vec` behind `&GraphBatch` — producing
/// per-key groupings from borrowed data requires cloning into fresh `Vec`s.
async fn write_batch<W: GraphWriter>(
    writer: &W,
    batch: &GraphBatch,
) -> Result<(), crate::error::GraphWriteError> {
    writer.upsert_enis(&batch.enis).await?;
    writer
        .upsert_security_groups(&batch.security_groups)
        .await?;
    writer.upsert_network_acls(&batch.network_acls).await?;
    writer.upsert_subnets(&batch.subnets).await?;
    writer.upsert_vpcs(&batch.vpcs).await?;
    writer.upsert_route_tables(&batch.route_tables).await?;

    let mut has_sg_edges = Vec::new();
    let mut in_subnet_edges = Vec::new();
    let mut protected_by_edges = Vec::new();
    let mut uses_route_table_edges = Vec::new();
    let mut routes_to_edges = Vec::new();
    let mut ingress_pairs = Vec::new();
    let mut egress_pairs = Vec::new();
    let mut nacl_pairs = Vec::new();

    for edge in &batch.edges {
        match edge {
            Edge::HasSg(edge) => has_sg_edges.push(edge.clone()),
            Edge::InSubnet(edge) => in_subnet_edges.push(edge.clone()),
            Edge::ProtectedBy(edge) => protected_by_edges.push(edge.clone()),
            Edge::UsesRouteTable(edge) => uses_route_table_edges.push(edge.clone()),
            Edge::RoutesTo(edge) => routes_to_edges.push(edge.clone()),
            Edge::AllowsIngress {
                security_group_id,
                rule,
            } => ingress_pairs.push((security_group_id.as_str(), rule)),
            Edge::AllowsEgress {
                security_group_id,
                rule,
            } => egress_pairs.push((security_group_id.as_str(), rule)),
            Edge::HasRule {
                network_acl_id,
                rule,
            } => nacl_pairs.push((network_acl_id.as_str(), rule)),
        }
    }

    writer.upsert_has_sg_edges(&has_sg_edges).await?;
    writer.upsert_in_subnet_edges(&in_subnet_edges).await?;
    writer
        .upsert_protected_by_edges(&protected_by_edges)
        .await?;
    writer
        .upsert_uses_route_table_edges(&uses_route_table_edges)
        .await?;
    writer.upsert_routes_to_edges(&routes_to_edges).await?;

    let ingress_by_sg = group_by(ingress_pairs.into_iter());
    let ingress_batches: Vec<SgRuleBatch<'_>> = ingress_by_sg
        .iter()
        .map(|(security_group_id, rules)| SgRuleBatch {
            security_group_id,
            rules,
        })
        .collect();
    writer.upsert_allows_ingress_rules(&ingress_batches).await?;

    let egress_by_sg = group_by(egress_pairs.into_iter());
    let egress_batches: Vec<SgRuleBatch<'_>> = egress_by_sg
        .iter()
        .map(|(security_group_id, rules)| SgRuleBatch {
            security_group_id,
            rules,
        })
        .collect();
    writer.upsert_allows_egress_rules(&egress_batches).await?;

    let rules_by_nacl = group_by(nacl_pairs.into_iter());
    let nacl_batches: Vec<NaclRuleBatch<'_>> = rules_by_nacl
        .iter()
        .map(|(network_acl_id, rules)| NaclRuleBatch {
            network_acl_id,
            rules,
        })
        .collect();
    writer.upsert_has_rules(&nacl_batches).await?;

    Ok(())
}
