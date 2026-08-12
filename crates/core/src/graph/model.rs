//! The graph batch `crate::ingest::map::topology::build_graph_batch`
//! produces: one node record per AWS resource plus every edge, ready for a
//! future `GraphWriter` implementation to upsert.
//!
//! Node records are reused directly from `crate::ports` rather than
//! duplicated here, since `ports.rs` already mirrors `crates/core/docs/schema.md`
//! one-for-one and `GraphWriter`'s upsert methods are typed against exactly
//! those structs.

use crate::domain::rule::{NaclRule, SgRule};
use crate::ports::{
    EniRecord, HasSgEdge, InSubnetEdge, NetworkAclRecord, ProtectedByEdge, RouteTableRecord,
    RoutesToEdge, SecurityGroupRecord, SubnetRecord, UsesRouteTableEdge, VpcRecord,
};

/// One graph edge, keyed to exactly one payload type per variant so an edge
/// can never carry a type/payload mismatch — there is no `String` edge-type
/// field anywhere on this type or its payloads.
///
/// Topology edge variants wrap the corresponding `crate::ports` edge struct
/// verbatim. The evaluable-rule edges (`AllowsIngress`/`AllowsEgress`/
/// `HasRule`) have no single-rule struct in `ports.rs` (only the
/// `SgRuleBatch`/`NaclRuleBatch` a `GraphWriter` call groups by owning
/// resource), so they carry their owning resource id alongside the rule
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edge {
    /// A `HAS_SG` edge: `ENI` → `SecurityGroup`.
    HasSg(HasSgEdge),
    /// An `IN_SUBNET` edge: `ENI` → `Subnet`.
    InSubnet(InSubnetEdge),
    /// A `PROTECTED_BY` edge: `Subnet` → `NetworkACL`.
    ProtectedBy(ProtectedByEdge),
    /// A `USES_ROUTE_TABLE` edge: `Subnet` → `RouteTable`.
    UsesRouteTable(UsesRouteTableEdge),
    /// A `ROUTES_TO` edge: `RouteTable` → `VPC`, or unresolved.
    RoutesTo(RoutesToEdge),
    /// An `ALLOWS_INGRESS` edge, owned by the `SecurityGroup` with `security_group_id`.
    AllowsIngress {
        /// The source `SecurityGroup.id` this rule belongs to.
        security_group_id: String,
        /// The ingress rule this edge carries.
        rule: SgRule,
    },
    /// An `ALLOWS_EGRESS` edge, owned by the `SecurityGroup` with `security_group_id`.
    AllowsEgress {
        /// The source `SecurityGroup.id` this rule belongs to.
        security_group_id: String,
        /// The egress rule this edge carries.
        rule: SgRule,
    },
    /// A `HAS_RULE` self-edge, owned by the `NetworkACL` with `network_acl_id`.
    HasRule {
        /// The `NetworkACL.id` this rule belongs to.
        network_acl_id: String,
        /// The NACL rule this edge carries.
        rule: NaclRule,
    },
}

/// The full set of nodes and edges derived from one ingestion pass, ready
/// for a future `GraphWriter` implementation to upsert. Contains no
/// `RegulatedBoundary` nodes — those are operator-assigned, not derived
/// from AWS topology, and out of scope for this mapping layer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraphBatch {
    /// `ENI` nodes, one per `NetworkInterface`.
    pub enis: Vec<EniRecord>,
    /// `SecurityGroup` nodes, one per `SecurityGroup`.
    pub security_groups: Vec<SecurityGroupRecord>,
    /// `NetworkACL` nodes, one per `NetworkAcl`.
    pub network_acls: Vec<NetworkAclRecord>,
    /// `Subnet` nodes, deduplicated by id across every collector response
    /// that references a subnet.
    pub subnets: Vec<SubnetRecord>,
    /// `VPC` nodes, deduplicated by id across every collector response
    /// that references a VPC.
    pub vpcs: Vec<VpcRecord>,
    /// `RouteTable` nodes, one per `RouteTable`.
    pub route_tables: Vec<RouteTableRecord>,
    /// Every topology and rule edge derived from this ingestion pass.
    pub edges: Vec<Edge>,
}
