//! Proves the three M0-T6 traits (`GraphWriter`, `Resolver`, `Evaluator`)
//! are actually implementable without a live Neo4j database.
//!
//! Each mock below is a minimal test fixture, not a product: no general
//! purpose in-memory graph, no Docker, no database. Run alongside the rest
//! of the plain `cargo test --workspace` job.

// Locking a freshly-constructed `Mutex` and unwrapping trivial constructors
// (e.g. `PortRange::new`) in test arrange steps is not the thing under test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Mutex;

use aws_net_hound_core::domain::{
    Action, Direction, Hop, NaclRule, NodeKind, PathEvidence, PortRange, ReachabilityFinding,
    RuleTarget, Severity, SgRule,
};
use aws_net_hound_core::error::{EvaluationError, GraphWriteError, ResolveError};
use aws_net_hound_core::ports::{
    BoxFuture, EniRecord, Evaluator, GraphWriter, HasSgEdge, InSubnetEdge, NaclRuleBatch,
    NetworkAclRecord, PathCandidate, ProtectedByEdge, RegulatedBoundaryRecord, ResolvedReference,
    Resolver, RouteTableRecord, RoutesToEdge, SecurityGroupRecord, SgRuleBatch, SubnetRecord,
    UsesRouteTableEdge, VpcRecord,
};
use pretty_assertions::assert_eq;

/// Minimal `GraphWriter` backed by `HashMap`s guarded by `std::sync::Mutex`.
/// Each upsert method inserts synchronously and returns an already-ready
/// future — there is no real I/O to await.
#[derive(Default)]
struct InMemoryGraphWriter {
    enis: Mutex<HashMap<String, EniRecord>>,
    security_groups: Mutex<HashMap<String, SecurityGroupRecord>>,
    network_acls: Mutex<HashMap<String, NetworkAclRecord>>,
    subnets: Mutex<HashMap<String, SubnetRecord>>,
    vpcs: Mutex<HashMap<String, VpcRecord>>,
    route_tables: Mutex<HashMap<String, RouteTableRecord>>,
    regulated_boundaries: Mutex<HashMap<String, RegulatedBoundaryRecord>>,
    has_sg_edges: Mutex<HashMap<(String, String), HasSgEdge>>,
    in_subnet_edges: Mutex<HashMap<(String, String), InSubnetEdge>>,
    protected_by_edges: Mutex<HashMap<(String, String), ProtectedByEdge>>,
    uses_route_table_edges: Mutex<HashMap<(String, String), UsesRouteTableEdge>>,
    routes_to_edges: Mutex<HashMap<(String, String), RoutesToEdge>>,
    egress_rules: Mutex<HashMap<String, Vec<SgRule>>>,
    ingress_rules: Mutex<HashMap<String, Vec<SgRule>>>,
    has_rules: Mutex<HashMap<String, Vec<NaclRule>>>,
}

impl InMemoryGraphWriter {
    /// Reads back a single upserted `ENI` by id, public-API surface for
    /// tests only (not part of `GraphWriter`).
    fn eni(&self, id: &str) -> Option<EniRecord> {
        self.enis.lock().unwrap().get(id).cloned()
    }

    /// Total node count across every node type, for asserting an upsert of
    /// "one of everything" landed.
    fn node_count(&self) -> usize {
        self.enis.lock().unwrap().len()
            + self.security_groups.lock().unwrap().len()
            + self.network_acls.lock().unwrap().len()
            + self.subnets.lock().unwrap().len()
            + self.vpcs.lock().unwrap().len()
            + self.route_tables.lock().unwrap().len()
            + self.regulated_boundaries.lock().unwrap().len()
    }

    /// Total topology-edge count across every edge type.
    fn edge_count(&self) -> usize {
        self.has_sg_edges.lock().unwrap().len()
            + self.in_subnet_edges.lock().unwrap().len()
            + self.protected_by_edges.lock().unwrap().len()
            + self.uses_route_table_edges.lock().unwrap().len()
            + self.routes_to_edges.lock().unwrap().len()
    }

    /// Total rule count (SG egress + SG ingress + NACL) across every batch.
    fn rule_count(&self) -> usize {
        self.egress_rules
            .lock()
            .unwrap()
            .values()
            .map(Vec::len)
            .sum::<usize>()
            + self
                .ingress_rules
                .lock()
                .unwrap()
                .values()
                .map(Vec::len)
                .sum::<usize>()
            + self
                .has_rules
                .lock()
                .unwrap()
                .values()
                .map(Vec::len)
                .sum::<usize>()
    }
}

/// Inserts `records` into `store`, keyed by `key_fn`, MERGE-style (repeated
/// upserts of the same key overwrite in place rather than duplicate).
fn upsert<K, V>(store: &Mutex<HashMap<K, V>>, key_fn: impl Fn(&V) -> K, records: &[V])
where
    K: Eq + std::hash::Hash,
    V: Clone,
{
    let mut guard = store.lock().unwrap();
    for record in records {
        guard.insert(key_fn(record), record.clone());
    }
}

impl GraphWriter for InMemoryGraphWriter {
    fn upsert_enis(&self, enis: &[EniRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.enis, |record| record.id.clone(), enis);
        Box::pin(async { Ok(()) })
    }

    fn upsert_security_groups(
        &self,
        security_groups: &[SecurityGroupRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(
            &self.security_groups,
            |record| record.id.clone(),
            security_groups,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_network_acls(
        &self,
        network_acls: &[NetworkAclRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.network_acls, |record| record.id.clone(), network_acls);
        Box::pin(async { Ok(()) })
    }

    fn upsert_subnets(
        &self,
        subnets: &[SubnetRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.subnets, |record| record.id.clone(), subnets);
        Box::pin(async { Ok(()) })
    }

    fn upsert_vpcs(&self, vpcs: &[VpcRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.vpcs, |record| record.id.clone(), vpcs);
        Box::pin(async { Ok(()) })
    }

    fn upsert_route_tables(
        &self,
        route_tables: &[RouteTableRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.route_tables, |record| record.id.clone(), route_tables);
        Box::pin(async { Ok(()) })
    }

    fn upsert_regulated_boundaries(
        &self,
        boundaries: &[RegulatedBoundaryRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(
            &self.regulated_boundaries,
            |record| record.id.clone(),
            boundaries,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_has_sg_edges(
        &self,
        edges: &[HasSgEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(
            &self.has_sg_edges,
            |edge| (edge.eni_id.clone(), edge.security_group_id.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_in_subnet_edges(
        &self,
        edges: &[InSubnetEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(
            &self.in_subnet_edges,
            |edge| (edge.eni_id.clone(), edge.subnet_id.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_protected_by_edges(
        &self,
        edges: &[ProtectedByEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(
            &self.protected_by_edges,
            |edge| (edge.subnet_id.clone(), edge.network_acl_id.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_uses_route_table_edges(
        &self,
        edges: &[UsesRouteTableEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(
            &self.uses_route_table_edges,
            |edge| (edge.subnet_id.clone(), edge.route_table_id.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_routes_to_edges(
        &self,
        edges: &[RoutesToEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(
            &self.routes_to_edges,
            |edge| (edge.route_table_id.clone(), edge.destination_cidr.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_allows_egress_rules(
        &self,
        batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let mut guard = self.egress_rules.lock().unwrap();
        for batch in batches {
            guard.insert(batch.security_group_id.to_string(), batch.rules.to_vec());
        }
        drop(guard);
        Box::pin(async { Ok(()) })
    }

    fn upsert_allows_ingress_rules(
        &self,
        batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let mut guard = self.ingress_rules.lock().unwrap();
        for batch in batches {
            guard.insert(batch.security_group_id.to_string(), batch.rules.to_vec());
        }
        drop(guard);
        Box::pin(async { Ok(()) })
    }

    fn upsert_has_rules(
        &self,
        batches: &[NaclRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        let mut guard = self.has_rules.lock().unwrap();
        for batch in batches {
            guard.insert(batch.network_acl_id.to_string(), batch.rules.to_vec());
        }
        drop(guard);
        Box::pin(async { Ok(()) })
    }
}

/// Minimal `Resolver` returning canned resolutions keyed by security group
/// id; anything not in the map is treated as legitimately unresolvable
/// (e.g. a cross-account reference in local-audit mode), not an error.
#[derive(Default)]
struct StaticResolver {
    resolutions: HashMap<String, bool>,
}

impl Resolver for StaticResolver {
    fn resolve_security_group_reference(
        &self,
        security_group_id: &str,
    ) -> BoxFuture<'_, Result<ResolvedReference, ResolveError>> {
        let resolved = self
            .resolutions
            .get(security_group_id)
            .copied()
            .unwrap_or(false);
        let security_group_id = security_group_id.to_string();
        Box::pin(async move {
            Ok(ResolvedReference {
                security_group_id,
                resolved,
            })
        })
    }
}

/// Minimal `Evaluator` exercising a trivial intersection: SG rules are
/// allow-only in AWS, so reachability requires both an egress and an
/// ingress rule to be present; NACL rules can deny, so the first rule in
/// each already-sorted (per `PathCandidate`'s contract) direction decides.
struct IntersectionEvaluator;

impl Evaluator for IntersectionEvaluator {
    fn evaluate(
        &self,
        candidate: &PathCandidate,
    ) -> BoxFuture<'_, Result<Option<ReachabilityFinding>, EvaluationError>> {
        let result = evaluate_candidate(candidate);
        Box::pin(async move { result })
    }
}

fn evaluate_candidate(
    candidate: &PathCandidate,
) -> Result<Option<ReachabilityFinding>, EvaluationError> {
    if candidate.hops.is_empty() {
        return Err(EvaluationError::EmptyPath);
    }

    let sg_allows = !candidate.security_group_egress_rules.is_empty()
        && !candidate.security_group_ingress_rules.is_empty();

    let nacl_allows = first_action_allows(&candidate.nacl_egress_rules)
        && first_action_allows(&candidate.nacl_ingress_rules);

    if !(sg_allows && nacl_allows) {
        return Ok(None);
    }

    Ok(Some(ReachabilityFinding {
        computed_at: "2026-08-08T00:00:00Z".to_string(),
        source: candidate.source.clone(),
        destination_boundary: candidate.destination_boundary.clone(),
        path_evidence: PathEvidence {
            hops: candidate.hops.clone(),
        },
        severity: Severity::High,
    }))
}

/// First-match-wins on an already rule-number-sorted slice, per
/// `PathCandidate::nacl_egress_rules`'s doc comment.
fn first_action_allows(rules: &[NaclRule]) -> bool {
    rules
        .first()
        .is_some_and(|rule| rule.action == Action::Allow)
}

fn sample_eni() -> EniRecord {
    EniRecord {
        id: "eni-0example".to_string(),
        account_id: "123456789012".to_string(),
        vpc_id: "vpc-0example".to_string(),
        subnet_id: "subnet-0example".to_string(),
        private_ip: "10.0.0.5".to_string(),
        description: None,
    }
}

fn allow_all_sg_rule(direction: Direction) -> SgRule {
    SgRule {
        direction,
        protocol: "tcp".to_string(),
        port_range: Some(PortRange::new(443, 443).expect("443..443 is a valid port range")),
        target: RuleTarget::Cidr {
            cidr: "0.0.0.0/0".to_string(),
        },
        resolved: true,
    }
}

fn nacl_rule(rule_number: u16, direction: Direction, action: Action) -> NaclRule {
    NaclRule {
        rule_number,
        direction,
        protocol: "tcp".to_string(),
        port_range: Some(PortRange::new(443, 443).expect("443..443 is a valid port range")),
        cidr: "0.0.0.0/0".to_string(),
        action,
    }
}

fn sample_hops() -> Vec<Hop> {
    vec![
        Hop {
            node_id: "eni-0example".to_string(),
            node_kind: NodeKind::Eni,
        },
        Hop {
            node_id: "boundary-pci-prod".to_string(),
            node_kind: NodeKind::RegulatedBoundary,
        },
    ]
}

#[tokio::test]
async fn in_memory_graph_writer_upsert_eni_then_read_back_returns_node() {
    // Arrange
    let writer = InMemoryGraphWriter::default();
    let eni = sample_eni();

    // Act
    writer
        .upsert_enis(std::slice::from_ref(&eni))
        .await
        .expect("upserting an ENI record succeeds");

    // Assert
    assert_eq!(writer.eni(&eni.id), Some(eni));
}

#[tokio::test]
async fn in_memory_graph_writer_upserts_every_node_edge_and_rule_type() {
    // Arrange
    let writer = InMemoryGraphWriter::default();
    let sg_rules = vec![allow_all_sg_rule(Direction::Egress)];
    let nacl_rules = vec![nacl_rule(100, Direction::Ingress, Action::Allow)];
    let egress_batch = [SgRuleBatch {
        security_group_id: "sg-0example",
        rules: &sg_rules,
    }];
    let ingress_batch = [SgRuleBatch {
        security_group_id: "sg-0example",
        rules: &sg_rules,
    }];
    let has_rules_batch = [NaclRuleBatch {
        network_acl_id: "acl-0example",
        rules: &nacl_rules,
    }];

    // Act
    writer
        .upsert_enis(&[sample_eni()])
        .await
        .expect("ENI upsert succeeds");
    writer
        .upsert_security_groups(&[SecurityGroupRecord {
            id: "sg-0example".to_string(),
            account_id: "123456789012".to_string(),
            vpc_id: "vpc-0example".to_string(),
            name: "web".to_string(),
            description: None,
        }])
        .await
        .expect("SecurityGroup upsert succeeds");
    writer
        .upsert_network_acls(&[NetworkAclRecord {
            id: "acl-0example".to_string(),
            account_id: "123456789012".to_string(),
            vpc_id: "vpc-0example".to_string(),
            is_default: false,
        }])
        .await
        .expect("NetworkACL upsert succeeds");
    writer
        .upsert_subnets(&[SubnetRecord {
            id: "subnet-0example".to_string(),
            account_id: "123456789012".to_string(),
            vpc_id: "vpc-0example".to_string(),
            cidr_block: "10.0.0.0/24".to_string(),
            availability_zone: "us-east-1a".to_string(),
        }])
        .await
        .expect("Subnet upsert succeeds");
    writer
        .upsert_vpcs(&[VpcRecord {
            id: "vpc-0example".to_string(),
            account_id: "123456789012".to_string(),
            cidr_block: "10.0.0.0/16".to_string(),
        }])
        .await
        .expect("VPC upsert succeeds");
    writer
        .upsert_route_tables(&[RouteTableRecord {
            id: "rtb-0example".to_string(),
            account_id: "123456789012".to_string(),
            vpc_id: "vpc-0example".to_string(),
            is_main: true,
        }])
        .await
        .expect("RouteTable upsert succeeds");
    writer
        .upsert_regulated_boundaries(&[RegulatedBoundaryRecord {
            id: "boundary-pci-prod".to_string(),
            account_id: "123456789012".to_string(),
            name: "PCI prod".to_string(),
            regime: "PCI-DSS".to_string(),
            description: None,
        }])
        .await
        .expect("RegulatedBoundary upsert succeeds");
    writer
        .upsert_has_sg_edges(&[HasSgEdge {
            eni_id: "eni-0example".to_string(),
            security_group_id: "sg-0example".to_string(),
        }])
        .await
        .expect("HAS_SG upsert succeeds");
    writer
        .upsert_in_subnet_edges(&[InSubnetEdge {
            eni_id: "eni-0example".to_string(),
            subnet_id: "subnet-0example".to_string(),
        }])
        .await
        .expect("IN_SUBNET upsert succeeds");
    writer
        .upsert_protected_by_edges(&[ProtectedByEdge {
            subnet_id: "subnet-0example".to_string(),
            network_acl_id: "acl-0example".to_string(),
        }])
        .await
        .expect("PROTECTED_BY upsert succeeds");
    writer
        .upsert_uses_route_table_edges(&[UsesRouteTableEdge {
            subnet_id: "subnet-0example".to_string(),
            route_table_id: "rtb-0example".to_string(),
        }])
        .await
        .expect("USES_ROUTE_TABLE upsert succeeds");
    writer
        .upsert_routes_to_edges(&[RoutesToEdge {
            route_table_id: "rtb-0example".to_string(),
            destination_cidr: "0.0.0.0/0".to_string(),
            target_vpc_id: None,
            resolved: false,
        }])
        .await
        .expect("ROUTES_TO upsert succeeds");
    writer
        .upsert_allows_egress_rules(&egress_batch)
        .await
        .expect("ALLOWS_EGRESS upsert succeeds");
    writer
        .upsert_allows_ingress_rules(&ingress_batch)
        .await
        .expect("ALLOWS_INGRESS upsert succeeds");
    writer
        .upsert_has_rules(&has_rules_batch)
        .await
        .expect("HAS_RULE upsert succeeds");

    // Assert
    assert_eq!(writer.node_count(), 7);
    assert_eq!(writer.edge_count(), 5);
    assert_eq!(writer.rule_count(), 3);
}

#[tokio::test]
async fn static_resolver_unknown_cross_account_reference_returns_unresolved_not_error() {
    // Arrange
    let mut resolutions = HashMap::new();
    resolutions.insert("sg-local-example".to_string(), true);
    let resolver = StaticResolver { resolutions };

    // Act
    let result = resolver
        .resolve_security_group_reference("sg-cross-account-unknown")
        .await
        .expect("an unresolvable reference is a successful outcome, not an error");

    // Assert
    assert_eq!(
        result,
        ResolvedReference {
            security_group_id: "sg-cross-account-unknown".to_string(),
            resolved: false,
        }
    );
}

#[tokio::test]
async fn evaluator_sg_allows_but_nacl_denies_returns_not_reachable() {
    // Arrange
    let evaluator = IntersectionEvaluator;
    let candidate = PathCandidate {
        source: "eni-0example".to_string(),
        destination_boundary: "boundary-pci-prod".to_string(),
        hops: sample_hops(),
        security_group_egress_rules: vec![allow_all_sg_rule(Direction::Egress)],
        security_group_ingress_rules: vec![allow_all_sg_rule(Direction::Ingress)],
        nacl_egress_rules: vec![nacl_rule(100, Direction::Egress, Action::Allow)],
        nacl_ingress_rules: vec![nacl_rule(100, Direction::Ingress, Action::Deny)],
    };

    // Act
    let result = evaluator
        .evaluate(&candidate)
        .await
        .expect("evaluation succeeds");

    // Assert
    assert_eq!(result, None);
}

#[tokio::test]
async fn evaluator_nacl_lower_numbered_deny_wins_over_higher_numbered_allow() {
    // Arrange
    let evaluator = IntersectionEvaluator;
    let candidate = PathCandidate {
        source: "eni-0example".to_string(),
        destination_boundary: "boundary-pci-prod".to_string(),
        hops: sample_hops(),
        security_group_egress_rules: vec![allow_all_sg_rule(Direction::Egress)],
        security_group_ingress_rules: vec![allow_all_sg_rule(Direction::Ingress)],
        nacl_egress_rules: vec![nacl_rule(100, Direction::Egress, Action::Allow)],
        // Sorted ascending, per `PathCandidate`'s contract: the lower rule
        // number (100, Deny) must win over the higher one (200, Allow).
        nacl_ingress_rules: vec![
            nacl_rule(100, Direction::Ingress, Action::Deny),
            nacl_rule(200, Direction::Ingress, Action::Allow),
        ],
    };

    // Act
    let result = evaluator
        .evaluate(&candidate)
        .await
        .expect("evaluation succeeds");

    // Assert
    assert_eq!(result, None);
}
