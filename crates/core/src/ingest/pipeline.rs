//! Orchestrates the full Milestone 1 ingestion pipeline: build the AWS
//! client, run the five collectors concurrently, map the results into a
//! graph batch, write it, and report what happened.
//!
//! [`run_full_ingest`] is the one entry point Milestone 3's CLI needs from
//! this crate's `ingest` module.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::error::{IngestError, MappingError};
use crate::graph::model::{Edge, GraphBatch};
use crate::ports::{GraphWriter, NaclRuleBatch, SgRuleBatch};

use super::aws_client::{build_sdk_config, resolve_account_id};
use super::collect::{
    collect_network_acls, collect_network_interfaces, collect_route_tables,
    collect_security_groups, collect_vpc_peering_connections,
};
use super::map::topology::{
    build_graph_batch, map_eni_node, map_network_acl_node, map_route_table_node,
    map_security_group_node,
};
use super::IngestConfig;

/// The kind of AWS resource an [`IngestWarning`] or an [`IngestReport`]
/// count refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ResourceKind {
    Eni,
    SecurityGroup,
    NetworkAcl,
    RouteTable,
    VpcPeeringConnection,
}

/// Why a single resource could not be mapped and was excluded from the
/// ingested graph. `#[non_exhaustive]`: a future mapper may fail for a
/// reason this variant set doesn't cover yet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub enum IngestWarningReason {
    /// A required field on the resource was missing or malformed. See
    /// [`MappingError::InvalidField`].
    InvalidField { field: &'static str, reason: String },
}

/// One resource that failed to map and was excluded from the run's graph
/// batch. The run continues — see [`run_full_ingest`]'s doc comment for why
/// this is non-fatal while a graph write failure is not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IngestWarning {
    pub resource_id: String,
    pub resource_kind: ResourceKind,
    pub reason: IngestWarningReason,
}

fn duration_as_secs_f64<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(duration.as_secs_f64())
}

/// The outcome of one [`run_full_ingest`] call.
///
/// An operator must be able to tell a clean, empty account apart from a
/// partially failed ingestion without a debugger: `counts` and
/// `unresolved_references` make that legible from the report alone, not
/// just from logs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
    /// Wall-clock time the run took, start to finish.
    #[serde(serialize_with = "duration_as_secs_f64")]
    pub duration: Duration,
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
/// the `crates/core/tests/ingest_pipeline.rs` integration suite can drive
/// the pipeline against an `aws-smithy-mocks` client and a fixed account id
/// directly, instead of depending on `aws_config`'s provider chain or a
/// real STS call — mirrors the
/// [`super::aws_client::build_ec2_client`]/`build_ec2_client_from_sources`
/// split. Not part of the crate's public API contract despite the `pub`
/// visibility required for integration tests to reach it.
#[doc(hidden)]
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

    let mut warnings = Vec::new();
    let network_interfaces = filter_mappable(
        account_id,
        &network_interfaces,
        map_eni_node,
        ResourceKind::Eni,
        &mut warnings,
    );
    let security_groups = filter_mappable(
        account_id,
        &security_groups,
        map_security_group_node,
        ResourceKind::SecurityGroup,
        &mut warnings,
    );
    let network_acls = filter_mappable(
        account_id,
        &network_acls,
        map_network_acl_node,
        ResourceKind::NetworkAcl,
        &mut warnings,
    );
    let route_tables = filter_mappable(
        account_id,
        &route_tables,
        map_route_table_node,
        ResourceKind::RouteTable,
        &mut warnings,
    );
    for warning in &warnings {
        warn!(
            resource_id = %warning.resource_id,
            resource_kind = ?warning.resource_kind,
            reason = ?warning.reason,
            "resource excluded from graph batch: failed to map"
        );
    }

    let batch = build_graph_batch(
        account_id,
        &security_groups,
        &network_acls,
        &route_tables,
        &network_interfaces,
        &vpc_peering_connections,
    )
    .map_err(|source| IngestError::Mapping { source })?;

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

    let duration = start.elapsed();
    info!(
        ?counts,
        unresolved_references,
        warnings = warnings.len(),
        duration_secs = duration.as_secs_f64(),
        "ingest complete"
    );

    Ok(IngestReport {
        counts,
        unresolved_references,
        duration,
        non_fatal: warnings,
    })
}

/// Filters `items` down to the ones `try_map_one` maps successfully,
/// recording an [`IngestWarning`] (via `id_of`, applied to the item before
/// mapping so a warning can still name the resource that failed) for every
/// one that doesn't. Mapping is pure and cheap, so re-running it here
/// (ahead of [`build_graph_batch`]'s own, identical mapping) costs nothing
/// beyond a second pass over what are typically small collections, and lets
/// one bad resource be excluded without aborting the whole batch — which
/// `build_graph_batch` cannot do on its own, since it propagates the first
/// `MappingError` via `?`.
fn filter_mappable<T, R>(
    account_id: &str,
    items: &[T],
    try_map_one: impl Fn(&T, &str) -> Result<R, MappingError>,
    resource_kind: ResourceKind,
    warnings: &mut Vec<IngestWarning>,
) -> Vec<T>
where
    T: Clone,
{
    items
        .iter()
        .filter(|item| match try_map_one(item, account_id) {
            Ok(_) => true,
            Err(MappingError::InvalidField {
                resource_id,
                field,
                reason,
            }) => {
                warnings.push(IngestWarning {
                    resource_id,
                    resource_kind,
                    reason: IngestWarningReason::InvalidField { field, reason },
                });
                false
            }
        })
        .cloned()
        .collect()
}

fn count_unresolved(batch: &GraphBatch) -> usize {
    batch
        .edges
        .iter()
        .filter(|edge| match edge {
            Edge::RoutesTo(edge) => !edge.resolved,
            Edge::AllowsIngress { rule, .. } | Edge::AllowsEgress { rule, .. } => !rule.resolved,
            _ => false,
        })
        .count()
}

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
    let mut ingress_by_sg: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    let mut egress_by_sg: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    let mut rules_by_nacl: BTreeMap<&str, Vec<_>> = BTreeMap::new();

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
            } => ingress_by_sg
                .entry(security_group_id.as_str())
                .or_default()
                .push(rule.clone()),
            Edge::AllowsEgress {
                security_group_id,
                rule,
            } => egress_by_sg
                .entry(security_group_id.as_str())
                .or_default()
                .push(rule.clone()),
            Edge::HasRule {
                network_acl_id,
                rule,
            } => rules_by_nacl
                .entry(network_acl_id.as_str())
                .or_default()
                .push(rule.clone()),
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

    let ingress_batches: Vec<SgRuleBatch<'_>> = ingress_by_sg
        .iter()
        .map(|(security_group_id, rules)| SgRuleBatch {
            security_group_id,
            rules,
        })
        .collect();
    writer.upsert_allows_ingress_rules(&ingress_batches).await?;

    let egress_batches: Vec<SgRuleBatch<'_>> = egress_by_sg
        .iter()
        .map(|(security_group_id, rules)| SgRuleBatch {
            security_group_id,
            rules,
        })
        .collect();
    writer.upsert_allows_egress_rules(&egress_batches).await?;

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
