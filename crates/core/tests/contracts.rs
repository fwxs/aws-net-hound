//! Proves the three M0-T6 traits (`GraphWriter`, `Resolver`, `Evaluator`)
//! are actually implementable without a live Neo4j database.
//!
//! Each mock below is a minimal test fixture, not a product: no general
//! purpose in-memory graph, no Docker, no database. Run alongside the rest
//! of the plain `cargo test --workspace` job.

// Locking a freshly-constructed `Mutex` and unwrapping trivial constructors
// (e.g. `PortRange::new`) in test arrange steps is not the thing under test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use aws_net_hound_core::domain::{
    Action, Direction, NaclRule, PortRange, Reachability, RuleTarget, Severity, SgRule,
};
use aws_net_hound_core::error::ResolveError;
use aws_net_hound_core::evaluate::path::{EndpointCandidate, EvaluationLayer, PathCandidate};
use aws_net_hound_core::evaluate::{Protocol, RuleIntersectionEvaluator, Traffic, Verdict};
use aws_net_hound_core::ports::{
    BoxFuture, EniRecord, Evaluator, GraphWriter, HasSgEdge, InSubnetEdge, NaclRuleBatch,
    NetworkAclRecord, ProtectedByEdge, RegulatedBoundaryRecord, ResolvedReference, Resolver,
    RouteTableRecord, RoutesToEdge, SecurityGroupRecord, SgRuleBatch, SubnetRecord,
    UsesRouteTableEdge, VpcRecord,
};
use common::InMemoryGraphWriter;
use pretty_assertions::assert_eq;

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

/// One concrete traffic flow shared across all four layers under test.
fn sample_traffic() -> Traffic {
    Traffic {
        protocol: Protocol::Tcp,
        port: Some(443),
        peer_address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
    }
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

fn sample_endpoint(
    eni_id: &str,
    security_group_rules: Vec<SgRule>,
    nacl_rules: Vec<NaclRule>,
) -> EndpointCandidate {
    EndpointCandidate {
        eni_id: eni_id.to_string(),
        peer_security_group_ids: Vec::new(),
        security_group_rules,
        subnet_id: "subnet-0example".to_string(),
        nacl_rules,
    }
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
async fn in_memory_graph_writer_upsert_twice_same_key_is_idempotent() {
    // Arrange
    let writer = InMemoryGraphWriter::default();
    let sg_rules = vec![allow_all_sg_rule(Direction::Egress)];
    let nacl_rules = vec![nacl_rule(100, Direction::Ingress, Action::Allow)];
    let egress_batch = [SgRuleBatch {
        security_group_id: "sg-0example",
        rules: &sg_rules,
    }];
    let has_rules_batch = [NaclRuleBatch {
        network_acl_id: "acl-0example",
        rules: &nacl_rules,
    }];
    let eni = sample_eni();
    let has_sg_edge = [HasSgEdge {
        eni_id: "eni-0example".to_string(),
        security_group_id: "sg-0example".to_string(),
    }];

    // Act: upsert the same eni, HAS_SG edge, and rule batch twice.
    for _ in 0..2 {
        writer
            .upsert_enis(std::slice::from_ref(&eni))
            .await
            .expect("ENI upsert succeeds");
        writer
            .upsert_has_sg_edges(&has_sg_edge)
            .await
            .expect("HAS_SG upsert succeeds");
        writer
            .upsert_allows_egress_rules(&egress_batch)
            .await
            .expect("ALLOWS_EGRESS upsert succeeds");
        writer
            .upsert_has_rules(&has_rules_batch)
            .await
            .expect("HAS_RULE upsert succeeds");
    }

    // Assert: the second, duplicate-key upsert created no duplicates.
    assert_eq!(writer.node_count(), 1);
    assert_eq!(writer.edge_count(), 1);
    assert_eq!(writer.rule_count(), 2);
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
async fn static_resolver_known_local_reference_returns_resolved() {
    // Arrange
    let mut resolutions = HashMap::new();
    resolutions.insert("sg-local-example".to_string(), true);
    let resolver = StaticResolver { resolutions };

    // Act
    let result = resolver
        .resolve_security_group_reference("sg-local-example")
        .await
        .expect("a known local reference resolves successfully");

    // Assert
    assert_eq!(
        result,
        ResolvedReference {
            security_group_id: "sg-local-example".to_string(),
            resolved: true,
        }
    );
}

#[tokio::test]
async fn evaluator_sg_allows_but_nacl_denies_returns_not_reachable() {
    // Arrange
    let evaluator = RuleIntersectionEvaluator;
    let candidate = PathCandidate {
        source: sample_endpoint(
            "eni-source",
            vec![allow_all_sg_rule(Direction::Egress)],
            vec![nacl_rule(100, Direction::Egress, Action::Allow)],
        ),
        destination: sample_endpoint(
            "eni-destination",
            vec![allow_all_sg_rule(Direction::Ingress)],
            vec![nacl_rule(100, Direction::Ingress, Action::Deny)],
        ),
        route_exists: true,
        traffic: sample_traffic(),
        destination_boundary: "boundary-pci-prod".to_string(),
    };

    // Act
    let result = evaluator
        .evaluate(&candidate)
        .await
        .expect("evaluation succeeds");

    // Assert
    assert_eq!(result.reachability, Reachability::NotReachable);
}

#[tokio::test]
async fn evaluator_sg_and_nacl_both_allow_returns_reachability_finding() {
    // Arrange
    let evaluator = RuleIntersectionEvaluator;
    let candidate = PathCandidate {
        source: sample_endpoint(
            "eni-source",
            vec![allow_all_sg_rule(Direction::Egress)],
            vec![nacl_rule(100, Direction::Egress, Action::Allow)],
        ),
        destination: sample_endpoint(
            "eni-destination",
            vec![allow_all_sg_rule(Direction::Ingress)],
            vec![nacl_rule(100, Direction::Ingress, Action::Allow)],
        ),
        route_exists: true,
        traffic: sample_traffic(),
        destination_boundary: "boundary-pci-prod".to_string(),
    };

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .expect("evaluation succeeds");

    // Assert
    assert_eq!(finding.reachability, Reachability::Reachable);
    assert_eq!(finding.source, "eni-source");
    assert_eq!(finding.destination_boundary, "boundary-pci-prod");
    assert_eq!(finding.severity, Severity::High);
    let layers: Vec<EvaluationLayer> = finding
        .path_evidence
        .steps
        .iter()
        .map(|step| step.layer)
        .collect();
    assert_eq!(
        layers,
        vec![
            EvaluationLayer::SgEgress,
            EvaluationLayer::NaclEgress,
            EvaluationLayer::NaclIngress,
            EvaluationLayer::SgIngress,
        ]
    );
    assert!(finding
        .path_evidence
        .steps
        .iter()
        .all(|step| matches!(step.verdict, Verdict::Allowed { .. })));
}

#[tokio::test]
async fn evaluator_nacl_lower_numbered_deny_wins_over_higher_numbered_allow() {
    // Arrange
    let evaluator = RuleIntersectionEvaluator;
    let candidate = PathCandidate {
        source: sample_endpoint(
            "eni-source",
            vec![allow_all_sg_rule(Direction::Egress)],
            vec![nacl_rule(100, Direction::Egress, Action::Allow)],
        ),
        destination: sample_endpoint(
            "eni-destination",
            vec![allow_all_sg_rule(Direction::Ingress)],
            // Sorted ascending, per `EndpointCandidate::nacl_rules`'s doc
            // comment: the lower rule number (100, Deny) must win over the
            // higher one (200, Allow).
            vec![
                nacl_rule(100, Direction::Ingress, Action::Deny),
                nacl_rule(200, Direction::Ingress, Action::Allow),
            ],
        ),
        route_exists: true,
        traffic: sample_traffic(),
        destination_boundary: "boundary-pci-prod".to_string(),
    };

    // Act
    let result = evaluator
        .evaluate(&candidate)
        .await
        .expect("evaluation succeeds");

    // Assert
    assert_eq!(result.reachability, Reachability::NotReachable);
}
