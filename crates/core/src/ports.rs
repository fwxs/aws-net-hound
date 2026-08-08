//! Core trait contracts (`GraphWriter`, `Resolver`, `Evaluator`) that seam
//! off the Neo4j driver from Milestone 2's evaluation logic.
//!
//! No Neo4j implementation lives here — see `crates/core/docs/schema.md`
//! for the node/edge shapes these traits write and read.

use std::future::Future;
use std::pin::Pin;

use crate::domain::{Hop, NaclRule, ReachabilityFinding, SgRule};
use crate::error::{EvaluationError, GraphWriteError, ResolveError};

/// A boxed, `Send` future, used so `GraphWriter`, `Resolver`, and `Evaluator`
/// stay object-safe (`dyn GraphWriter`, etc.) — `-> impl Future` in a public
/// trait is not, since the concrete future type can't be named for a vtable.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A node or edge record accepted by a [`GraphWriter`] upsert method.
///
/// For node records (this one and the ones below it up to [`RoutesToEdge`]),
/// the first field is the upsert key: implementors must match on it (`MERGE`
/// semantics), not insert unconditionally, so re-ingesting the same AWS
/// resource updates it in place rather than duplicating it. Edge records key
/// on the combination of their endpoint fields instead — see each edge's own
/// doc comment for its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EniRecord {
    pub id: String,
    pub account_id: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub private_ip: String,
    pub description: Option<String>,
}

/// A `SecurityGroup` node record. See [`EniRecord`] for upsert-key semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroupRecord {
    pub id: String,
    pub account_id: String,
    pub vpc_id: String,
    pub name: String,
    pub description: Option<String>,
}

/// A `NetworkACL` node record. See [`EniRecord`] for upsert-key semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAclRecord {
    pub id: String,
    pub account_id: String,
    pub vpc_id: String,
    pub is_default: bool,
}

/// A `Subnet` node record. See [`EniRecord`] for upsert-key semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetRecord {
    pub id: String,
    pub account_id: String,
    pub vpc_id: String,
    pub cidr_block: String,
    pub availability_zone: String,
}

/// A `VPC` node record. See [`EniRecord`] for upsert-key semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpcRecord {
    pub id: String,
    pub account_id: String,
    pub cidr_block: String,
}

/// A `RouteTable` node record. See [`EniRecord`] for upsert-key semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTableRecord {
    pub id: String,
    pub account_id: String,
    pub vpc_id: String,
    pub is_main: bool,
}

/// A `RegulatedBoundary` node record, operator-assigned rather than sourced
/// from AWS. See [`EniRecord`] for upsert-key semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegulatedBoundaryRecord {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub regime: String,
    pub description: Option<String>,
}

/// A `HAS_SG` edge: `ENI` → `SecurityGroup` membership, no properties.
/// Keyed on `(eni_id, security_group_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HasSgEdge {
    pub eni_id: String,
    pub security_group_id: String,
}

/// An `IN_SUBNET` edge: `ENI` → `Subnet`, no properties. Keyed on
/// `(eni_id, subnet_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InSubnetEdge {
    pub eni_id: String,
    pub subnet_id: String,
}

/// A `PROTECTED_BY` edge: `Subnet` → `NetworkACL`, no properties. Keyed on
/// `(subnet_id, network_acl_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedByEdge {
    pub subnet_id: String,
    pub network_acl_id: String,
}

/// A `USES_ROUTE_TABLE` edge: `Subnet` → `RouteTable`, no properties. Keyed
/// on `(subnet_id, route_table_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsesRouteTableEdge {
    pub subnet_id: String,
    pub route_table_id: String,
}

/// A `ROUTES_TO` edge: `RouteTable` → target, where target is a `VPC` node
/// id when `resolved` is `true`, or absent (internet/NAT gateway, peering
/// connection) when `false` — see `schema.md`'s `ROUTES_TO` notes. Keyed on
/// `(route_table_id, destination_cidr)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutesToEdge {
    pub route_table_id: String,
    pub destination_cidr: String,
    pub target_vpc_id: Option<String>,
    pub resolved: bool,
}

/// Upsert methods for every node and edge type in `crates/core/docs/schema.md`.
///
/// # Contract
///
/// Implementors must treat every method as an idempotent `MERGE` keyed on
/// each record's first field (see [`EniRecord`]'s doc comment) — calling a
/// method twice with the same records must not create duplicates. Methods
/// take slices so a caller can batch thousands of records (e.g. a full
/// Milestone 1 ENI ingestion) into one call rather than one round trip per
/// item. An empty slice is a valid, successful no-op.
pub trait GraphWriter {
    /// Upserts `ENI` nodes. See the struct contract on [`GraphWriter`].
    fn upsert_enis(&self, enis: &[EniRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `SecurityGroup` nodes. See the struct contract on [`GraphWriter`].
    fn upsert_security_groups(
        &self,
        security_groups: &[SecurityGroupRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `NetworkACL` nodes. See the struct contract on [`GraphWriter`].
    fn upsert_network_acls(
        &self,
        network_acls: &[NetworkAclRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `Subnet` nodes. See the struct contract on [`GraphWriter`].
    fn upsert_subnets(
        &self,
        subnets: &[SubnetRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `VPC` nodes. See the struct contract on [`GraphWriter`].
    fn upsert_vpcs(&self, vpcs: &[VpcRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `RouteTable` nodes. See the struct contract on [`GraphWriter`].
    fn upsert_route_tables(
        &self,
        route_tables: &[RouteTableRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `RegulatedBoundary` nodes. See the struct contract on [`GraphWriter`].
    fn upsert_regulated_boundaries(
        &self,
        boundaries: &[RegulatedBoundaryRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `HAS_SG` edges. See the struct contract on [`GraphWriter`].
    fn upsert_has_sg_edges(
        &self,
        edges: &[HasSgEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `IN_SUBNET` edges. See the struct contract on [`GraphWriter`].
    fn upsert_in_subnet_edges(
        &self,
        edges: &[InSubnetEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `PROTECTED_BY` edges. See the struct contract on [`GraphWriter`].
    fn upsert_protected_by_edges(
        &self,
        edges: &[ProtectedByEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `USES_ROUTE_TABLE` edges. See the struct contract on [`GraphWriter`].
    fn upsert_uses_route_table_edges(
        &self,
        edges: &[UsesRouteTableEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `ROUTES_TO` edges. See the struct contract on [`GraphWriter`].
    fn upsert_routes_to_edges(
        &self,
        edges: &[RoutesToEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `ALLOWS_EGRESS` edges across `batches` (one entry per source
    /// `SecurityGroup`), keyed on `security_group_id` plus each rule's
    /// fields. Rules with `resolved: false` (unresolvable cross-account
    /// `SecurityGroupRef`) must still be written, never dropped, per
    /// `schema.md`.
    fn upsert_allows_egress_rules(
        &self,
        batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `ALLOWS_INGRESS` edges across `batches`. Same unresolved-rule
    /// contract as [`GraphWriter::upsert_allows_egress_rules`].
    fn upsert_allows_ingress_rules(
        &self,
        batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;

    /// Upserts `HAS_RULE` self-edges across `batches` (one entry per
    /// `NetworkACL`), keyed on `network_acl_id` plus each rule's
    /// `rule_number` (never insertion order — see `NaclRule::rule_number`'s
    /// doc comment).
    fn upsert_has_rules(
        &self,
        batches: &[NaclRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>>;
}

/// One `SecurityGroup`'s rules for a single [`GraphWriter`] egress/ingress
/// upsert call, batched alongside other security groups' rules in one slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgRuleBatch<'a> {
    pub security_group_id: &'a str,
    pub rules: &'a [SgRule],
}

/// One `NetworkACL`'s rules for a single [`GraphWriter::upsert_has_rules`]
/// call, batched alongside other network ACLs' rules in one slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaclRuleBatch<'a> {
    pub network_acl_id: &'a str,
    pub rules: &'a [NaclRule],
}

/// The outcome of attempting to resolve an ambiguous reference (e.g. an
/// `SgRule::target`'s `SecurityGroupRef` pointing at another security
/// group).
///
/// `resolved: false` is a successful, expected outcome — most commonly a
/// cross-account reference that local-audit mode cannot dereference — and
/// must not be modeled as an `Err`. Reserve `Err` (see [`ResolveError`])
/// for transport failures or malformed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedReference {
    /// The security group id that was looked up.
    pub security_group_id: String,
    /// Whether the reference could be dereferenced to a known node.
    pub resolved: bool,
}

/// Resolves ambiguous references that a `GraphWriter` upsert cannot decide
/// on its own — currently, whether an `SgRule::target`'s
/// `SecurityGroupRef` points at a security group visible in this audit's
/// scope.
///
/// # Contract
///
/// Implementors must return `Ok(ResolvedReference { resolved: false, .. })`
/// for a reference that is legitimately unresolvable in the current audit
/// scope (e.g. cross-account in local-audit mode) — this is expected, not
/// exceptional. `Err` is reserved for failures the caller cannot reason
/// about (transport failure, malformed input) per [`ResolveError`].
pub trait Resolver {
    /// Resolves a security-group-reference target to whether it points at
    /// a security group known in the current audit scope.
    fn resolve_security_group_reference(
        &self,
        security_group_id: &str,
    ) -> BoxFuture<'_, Result<ResolvedReference, ResolveError>>;
}

/// A materialized reachability path candidate for an [`Evaluator`] to
/// judge, composed entirely of `core::domain` types with no database
/// dependency — the caller (Milestone 2) is responsible for loading these
/// from wherever the graph data lives before calling [`Evaluator::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCandidate {
    /// Unique key of the source node the candidate path starts from.
    pub source: String,
    /// `RegulatedBoundary.id` the candidate path is being evaluated against.
    pub destination_boundary: String,
    /// Hops traversed, in traversal order (source first, destination last).
    pub hops: Vec<Hop>,
    /// Security group egress rules to intersect along the path.
    pub security_group_egress_rules: Vec<SgRule>,
    /// Security group ingress rules to intersect along the path.
    pub security_group_ingress_rules: Vec<SgRule>,
    /// Network ACL egress rules to intersect along the path, already
    /// sorted by ascending `rule_number` (first match wins).
    pub nacl_egress_rules: Vec<NaclRule>,
    /// Network ACL ingress rules to intersect along the path, already
    /// sorted by ascending `rule_number` (first match wins).
    pub nacl_ingress_rules: Vec<NaclRule>,
}

/// Judges whether a materialized [`PathCandidate`] represents real traffic
/// reachability, by intersecting security group egress/ingress and NACL
/// egress/ingress rules.
///
/// # Contract
///
/// This trait must never mention Neo4j, the driver, or any database type
/// in its signature — Milestone 2 depends on being able to unit-test SG/NACL
/// intersection logic (correctness-critical) without a live database.
/// Implementors may assume `candidate` is already fully materialized (no
/// further graph traversal needed) and must return `Ok(None)` — not an
/// `Err` — when the candidate does not represent reachable traffic.
pub trait Evaluator {
    /// Evaluates one path candidate, returning `Ok(Some(finding))` when
    /// traffic reaches the destination boundary, `Ok(None)` when it is
    /// blocked by an SG or NACL rule, or `Err` when the candidate itself
    /// is structurally invalid (e.g. empty `hops`).
    fn evaluate(
        &self,
        candidate: &PathCandidate,
    ) -> BoxFuture<'_, Result<Option<ReachabilityFinding>, EvaluationError>>;
}
