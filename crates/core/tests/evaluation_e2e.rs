//! M2-T7: proves `RuleIntersectionEvaluator` wires the right rule set to the
//! right layer end-to-end, driven through hand-built `PathCandidate`s only.
//!
//! No Neo4j, no Docker, no AWS credentials — runs in the plain
//! `cargo test --workspace` job. Each test mutates exactly one layer of a
//! shared fully-permissive baseline candidate, so the diff between "reachable"
//! and any given test is exactly the layer that test is about.

// Arrange-step convenience constructors (`PortRange::new(...).expect(...)`)
// are not the thing under test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};

use aws_net_hound_core::domain::rule::{
    Action, Direction, NaclRule, PortRange, RuleTarget, SgRule,
};
use aws_net_hound_core::domain::{Reachability, Severity};
use aws_net_hound_core::evaluate::path::{EndpointCandidate, EvaluationLayer, PathCandidate};
use aws_net_hound_core::evaluate::{
    DenyReason, IndeterminateReason, Protocol, RuleIntersectionEvaluator, RuleRef, Traffic, Verdict,
};
use aws_net_hound_core::ports::Evaluator;
use pretty_assertions::assert_eq;

fn sample_traffic() -> Traffic {
    Traffic {
        protocol: Protocol::Tcp,
        port: Some(443),
        peer_address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
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

fn unresolved_sg_ref_rule(direction: Direction, security_group_id: &str) -> SgRule {
    SgRule {
        direction,
        protocol: "tcp".to_string(),
        port_range: Some(PortRange::new(443, 443).expect("443..443 is a valid port range")),
        target: RuleTarget::SecurityGroupRef {
            security_group_id: security_group_id.to_string(),
        },
        resolved: false,
    }
}

fn allow_all_nacl_rule(rule_number: u16, direction: Direction) -> NaclRule {
    NaclRule {
        rule_number,
        direction,
        protocol: "tcp".to_string(),
        port_range: Some(PortRange::new(443, 443).expect("443..443 is a valid port range")),
        cidr: "0.0.0.0/0".to_string(),
        action: Action::Allow,
    }
}

fn deny_all_nacl_rule(rule_number: u16, direction: Direction) -> NaclRule {
    NaclRule {
        rule_number,
        direction,
        protocol: "tcp".to_string(),
        port_range: Some(PortRange::new(443, 443).expect("443..443 is a valid port range")),
        cidr: "0.0.0.0/0".to_string(),
        action: Action::Deny,
    }
}

fn permissive_endpoint(eni_id: &str, subnet_id: &str) -> EndpointCandidate {
    EndpointCandidate {
        eni_id: eni_id.to_string(),
        peer_security_group_ids: Vec::new(),
        security_group_rules: vec![
            allow_all_sg_rule(Direction::Egress),
            allow_all_sg_rule(Direction::Ingress),
        ],
        subnet_id: subnet_id.to_string(),
        nacl_rules: vec![
            allow_all_nacl_rule(100, Direction::Egress),
            allow_all_nacl_rule(100, Direction::Ingress),
        ],
    }
}

/// Fully-permissive baseline: route exists, SG egress/ingress allow-all, both
/// NACLs allow-all. Every test below mutates exactly one field of this.
fn fully_permissive_candidate() -> PathCandidate {
    PathCandidate {
        source: permissive_endpoint("eni-0source", "subnet-0source"),
        destination: permissive_endpoint("eni-0destination", "subnet-0destination"),
        route_exists: true,
        traffic: sample_traffic(),
        destination_boundary: "boundary-pci-prod".to_string(),
    }
}

fn layers_of(finding: &aws_net_hound_core::domain::ReachabilityFinding) -> Vec<EvaluationLayer> {
    finding
        .path_evidence
        .steps
        .iter()
        .map(|step| step.layer)
        .collect()
}

#[tokio::test]
async fn evaluate_path_all_layers_allow_returns_reachable() {
    // Arrange
    let candidate = fully_permissive_candidate();
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    assert_eq!(finding.reachability, Reachability::Reachable);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(
        layers_of(&finding),
        vec![
            EvaluationLayer::SgEgress,
            EvaluationLayer::NaclEgress,
            EvaluationLayer::NaclIngress,
            EvaluationLayer::SgIngress,
        ]
    );
}

#[tokio::test]
async fn evaluate_path_source_sg_egress_denies_returns_not_reachable() {
    // Arrange: no egress rule at all -> SG evaluates to no matching rule.
    let mut candidate = fully_permissive_candidate();
    candidate.source.security_group_rules = Vec::new();
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    assert_eq!(finding.reachability, Reachability::NotReachable);
    assert_eq!(layers_of(&finding), vec![EvaluationLayer::SgEgress]);
    let deciding_step = &finding.path_evidence.steps[0];
    assert_eq!(
        deciding_step.verdict,
        Verdict::Denied {
            reason: DenyReason::NoMatchingRule
        }
    );
}

#[tokio::test]
async fn evaluate_path_destination_sg_ingress_denies_returns_not_reachable() {
    // Arrange: destination has no ingress rule. Guards against a
    // source/destination transposition: every other layer stays permissive,
    // so all four evidence steps must still appear, with the last one denied.
    let mut candidate = fully_permissive_candidate();
    candidate.destination.security_group_rules = Vec::new();
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    assert_eq!(finding.reachability, Reachability::NotReachable);
    assert_eq!(
        layers_of(&finding),
        vec![
            EvaluationLayer::SgEgress,
            EvaluationLayer::NaclEgress,
            EvaluationLayer::NaclIngress,
            EvaluationLayer::SgIngress,
        ]
    );
    let deciding_step = finding
        .path_evidence
        .steps
        .last()
        .unwrap_or_else(|| panic!("four layers must be present"));
    assert_eq!(
        deciding_step.verdict,
        Verdict::Denied {
            reason: DenyReason::NoMatchingRule
        }
    );
}

#[tokio::test]
async fn evaluate_path_source_subnet_nacl_egress_denies_returns_not_reachable() {
    // Arrange
    let mut candidate = fully_permissive_candidate();
    candidate.source.nacl_rules = vec![deny_all_nacl_rule(100, Direction::Egress)];
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    assert_eq!(finding.reachability, Reachability::NotReachable);
    assert_eq!(
        layers_of(&finding),
        vec![EvaluationLayer::SgEgress, EvaluationLayer::NaclEgress]
    );
    let deciding_step = &finding.path_evidence.steps[1];
    assert_eq!(deciding_step.resource_id, "subnet-0source");
}

#[tokio::test]
async fn evaluate_path_destination_subnet_nacl_ingress_denies_returns_not_reachable() {
    // Arrange
    let mut candidate = fully_permissive_candidate();
    candidate.destination.nacl_rules = vec![deny_all_nacl_rule(100, Direction::Ingress)];
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    assert_eq!(finding.reachability, Reachability::NotReachable);
    assert_eq!(
        layers_of(&finding),
        vec![
            EvaluationLayer::SgEgress,
            EvaluationLayer::NaclEgress,
            EvaluationLayer::NaclIngress,
        ]
    );
    let deciding_step = &finding.path_evidence.steps[2];
    assert_eq!(deciding_step.resource_id, "subnet-0destination");
}

#[tokio::test]
async fn evaluate_path_no_route_returns_not_reachable_with_empty_evidence() {
    // Arrange: `engine.rs` deliberately returns zero evidence steps when no
    // route exists — there is no path to intersect at all, so no layer is
    // ever consulted (see `evaluate_candidate`'s `route_exists` guard).
    let mut candidate = fully_permissive_candidate();
    candidate.route_exists = false;
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    assert_eq!(finding.reachability, Reachability::NotReachable);
    assert!(finding.path_evidence.steps.is_empty());
}

#[tokio::test]
async fn evaluate_path_unresolved_cross_account_sg_reference_returns_indeterminate() {
    // Arrange
    let mut candidate = fully_permissive_candidate();
    candidate.source.security_group_rules = vec![unresolved_sg_ref_rule(
        Direction::Egress,
        "sg-cross-account",
    )];
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert: indeterminate, and explicitly not the false-negative outcome.
    assert_eq!(
        finding.reachability,
        Reachability::Indeterminate {
            layers: vec![EvaluationLayer::SgEgress]
        }
    );
    assert_ne!(finding.reachability, Reachability::NotReachable);
    let deciding_step = &finding.path_evidence.steps[0];
    assert_eq!(
        deciding_step.verdict,
        Verdict::Indeterminate {
            reason: IndeterminateReason::UnresolvedReference {
                security_group_id: "sg-cross-account".to_string()
            }
        }
    );
}

#[tokio::test]
async fn evaluate_path_unresolved_reference_with_nacl_deny_returns_not_reachable() {
    // Arrange: the source's egress rule set carries an unresolved
    // cross-account reference *alongside* an allow-all rule, so that layer
    // still resolves to `Allowed` (SG rules union: allow beats
    // indeterminate, see `sg::combine`) and evaluation proceeds to the NACL
    // ingress deny. `RuleIntersectionEvaluator` short-circuits on the first
    // non-`Allowed` layer, so a deny-vs-indeterminate race across two
    // *different, both-consulted* layers is unreachable in practice — this
    // exercises the realistic version: an indeterminate rule that never ends
    // up mattering because a later layer definitively denies first.
    let mut candidate = fully_permissive_candidate();
    candidate.source.security_group_rules = vec![
        allow_all_sg_rule(Direction::Egress),
        unresolved_sg_ref_rule(Direction::Egress, "sg-cross-account"),
    ];
    candidate.destination.nacl_rules = vec![deny_all_nacl_rule(100, Direction::Ingress)];
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    assert_eq!(finding.reachability, Reachability::NotReachable);
    assert_eq!(
        layers_of(&finding),
        vec![
            EvaluationLayer::SgEgress,
            EvaluationLayer::NaclEgress,
            EvaluationLayer::NaclIngress,
        ]
    );
}

#[tokio::test]
async fn evaluate_path_denied_finding_evidence_names_deciding_rule() {
    // Arrange: an explicit NACL deny (not the implicit fall-through) so the
    // evidence must name the specific rule that decided the outcome.
    let mut candidate = fully_permissive_candidate();
    candidate.destination.nacl_rules = vec![deny_all_nacl_rule(50, Direction::Ingress)];
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    let deciding_step = finding
        .path_evidence
        .steps
        .last()
        .unwrap_or_else(|| panic!("a NACL ingress deny must leave a deciding evidence step"));
    assert_eq!(deciding_step.layer, EvaluationLayer::NaclIngress);
    assert_eq!(
        deciding_step.verdict,
        Verdict::Denied {
            reason: DenyReason::ExplicitDeny {
                matched_by: RuleRef::NetworkAcl {
                    network_acl_id: "subnet-0destination".to_string(),
                    rule_number: 50,
                }
            }
        }
    );
}

#[tokio::test]
async fn evaluate_path_reachable_finding_evidence_contains_four_steps() {
    // Arrange
    let candidate = fully_permissive_candidate();
    let evaluator = RuleIntersectionEvaluator;

    // Act
    let finding = evaluator
        .evaluate(&candidate)
        .await
        .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

    // Assert
    assert_eq!(finding.path_evidence.steps.len(), 4);
    assert!(finding
        .path_evidence
        .steps
        .iter()
        .all(|step| matches!(step.verdict, Verdict::Allowed { .. })));
}
