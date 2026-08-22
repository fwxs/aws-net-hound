//! Materialized reachability path candidate and structured evaluation
//! evidence (M2-T5), assembled from what the SG (M2-T2) and NACL (M2-T3)
//! evaluators actually consume and return.

use serde::{Deserialize, Serialize};

use crate::domain::rule::{NaclRule, SgRule};
use crate::evaluate::{Traffic, Verdict};

/// One endpoint (source or destination) of a [`PathCandidate`].
///
/// Owns every field rather than borrowing, unlike
/// [`crate::evaluate::sg::PeerIdentity`] — a `PathCandidate` must be plain,
/// serializable data with no lifetime (see [`PathCandidate`]'s doc comment),
/// so the M2-T6 caller borrows a `&[String]` slice from
/// [`EndpointCandidate::peer_security_group_ids`] when constructing a
/// `PeerIdentity` at evaluation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointCandidate {
    /// Unique key of the `ENI` at this endpoint (e.g. `eni-0example`).
    pub eni_id: String,
    /// Security group ids this ENI is a member of (`HAS_SG` edges), used to
    /// match [`crate::domain::rule::RuleTarget::SecurityGroupRef`] rules.
    pub peer_security_group_ids: Vec<String>,
    /// Security group rules to intersect for this endpoint: egress rules
    /// when this is [`PathCandidate::source`], ingress rules when this is
    /// [`PathCandidate::destination`].
    pub security_group_rules: Vec<SgRule>,
    /// Unique key of the `Subnet` this ENI is in (`IN_SUBNET` edge).
    pub subnet_id: String,
    /// Network ACL rules protecting this endpoint's subnet
    /// (`PROTECTED_BY` → `HAS_RULE`), already sorted by ascending
    /// `rule_number` — NACL evaluation is first-match, never insertion
    /// order.
    pub nacl_rules: Vec<NaclRule>,
}

/// A materialized reachability path candidate for an [`crate::ports::Evaluator`]
/// to judge, composed entirely of `core::domain` types with no database
/// dependency — the caller (Milestone 2) is responsible for loading these
/// from wherever the graph data lives before calling
/// [`crate::ports::Evaluator::evaluate`].
///
/// Contains no trait objects, handles, `Arc`, or async — plain data, so it
/// round-trips through serde without loss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathCandidate {
    /// The traffic's source endpoint.
    pub source: EndpointCandidate,
    /// The traffic's destination endpoint.
    pub destination: EndpointCandidate,
    /// Whether a route exists from `source` to `destination`.
    ///
    /// Decided upstream by the `ROUTES_TO` graph traversal (see
    /// `schema.md`) — this field is trusted input to evaluation, not
    /// something this module recomputes. A plain `bool` is correct here
    /// specifically because the graph query has already collapsed route
    /// resolution to a binary fact; if route resolution ever becomes
    /// indeterminate, it should become a [`Verdict`] like every other
    /// layer.
    pub route_exists: bool,
    /// The concrete traffic flow being evaluated across all four layers.
    ///
    /// Owned here, not a second argument to
    /// [`crate::ports::Evaluator::evaluate`], so the candidate stays the
    /// single self-contained unit of work the trait's `&PathCandidate`-only
    /// signature requires.
    pub traffic: Traffic,
    /// `RegulatedBoundary.id` this candidate's destination is being judged
    /// against — matched by key, not graph traversal, per `schema.md`. Kept
    /// here for the same reason as `traffic`: the evaluator only ever sees
    /// `&PathCandidate`.
    pub destination_boundary: String,
}

/// One of the four rule layers an [`EvaluationStep`] can be evaluated
/// against, in the order a full (non-short-circuited) evaluation consults
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationLayer {
    /// [`PathCandidate::source`]'s security group egress rules.
    SgEgress,
    /// [`PathCandidate::source`]'s subnet's network ACL egress rules.
    NaclEgress,
    /// [`PathCandidate::destination`]'s subnet's network ACL ingress rules.
    NaclIngress,
    /// [`PathCandidate::destination`]'s security group ingress rules.
    SgIngress,
}

/// One layer's evaluation result, carrying enough to explain a finding
/// without re-investigating the account by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationStep {
    /// Which layer this step evaluated.
    pub layer: EvaluationLayer,
    /// The security group or network ACL id evaluated against.
    pub resource_id: String,
    /// The verdict this layer reached, carrying the deciding rule
    /// reference (see [`Verdict`]).
    pub verdict: Verdict,
}

/// The structured evidence an evaluator produced while judging a
/// [`PathCandidate`], one [`EvaluationStep`] per layer consulted, in the
/// order consulted.
///
/// No field here is a pre-rendered human-readable string — Milestone 4
/// formats. Because evaluation short-circuits on the first non-`Allowed`
/// verdict, this vector is legitimately shorter than four steps on a deny:
/// the last step is the deciding one, and the absence of successors after
/// it is information, not truncation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathEvidence {
    /// Steps taken, in evaluation order.
    pub steps: Vec<EvaluationStep>,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pretty_assertions::assert_eq;

    use super::*;
    use crate::domain::rule::{Direction, RuleTarget};
    use crate::evaluate::{DenyReason, Protocol, RuleRef};

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
            port_range: None,
            target: RuleTarget::Cidr {
                cidr: "0.0.0.0/0".to_string(),
            },
            resolved: false,
        }
    }

    fn sample_endpoint(eni_id: &str, sg_rules: Vec<SgRule>) -> EndpointCandidate {
        EndpointCandidate {
            eni_id: eni_id.to_string(),
            peer_security_group_ids: vec!["sg-0example".to_string()],
            security_group_rules: sg_rules,
            subnet_id: "subnet-0example".to_string(),
            nacl_rules: Vec::new(),
        }
    }

    #[test]
    fn path_evidence_serializes_steps_in_evaluation_order() {
        // Arrange
        let evidence = PathEvidence {
            steps: vec![
                EvaluationStep {
                    layer: EvaluationLayer::SgEgress,
                    resource_id: "sg-0example".to_string(),
                    verdict: Verdict::Allowed {
                        matched_by: RuleRef::SecurityGroup {
                            security_group_id: "sg-0example".to_string(),
                            rule_index: 0,
                        },
                    },
                },
                EvaluationStep {
                    layer: EvaluationLayer::NaclEgress,
                    resource_id: "acl-0example".to_string(),
                    verdict: Verdict::Denied {
                        reason: DenyReason::NoMatchingRule,
                    },
                },
            ],
        };

        // Act
        let serialized = serde_norway::to_string(&evidence)
            .unwrap_or_else(|error| panic!("failed to serialize PathEvidence: {error}"));
        let roundtripped: PathEvidence = serde_norway::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize PathEvidence: {error}"));

        // Assert
        assert_eq!(roundtripped, evidence);
        let layers: Vec<EvaluationLayer> =
            roundtripped.steps.iter().map(|step| step.layer).collect();
        assert_eq!(
            layers,
            vec![EvaluationLayer::SgEgress, EvaluationLayer::NaclEgress]
        );
    }

    #[test]
    fn path_candidate_round_trips_through_serde_without_losing_unresolved_flag() {
        // Arrange
        let candidate = PathCandidate {
            source: sample_endpoint("eni-source", vec![allow_all_sg_rule(Direction::Egress)]),
            destination: sample_endpoint(
                "eni-destination",
                vec![allow_all_sg_rule(Direction::Ingress)],
            ),
            route_exists: true,
            traffic: sample_traffic(),
            destination_boundary: "boundary-pci-prod".to_string(),
        };

        // Act
        let serialized = serde_norway::to_string(&candidate)
            .unwrap_or_else(|error| panic!("failed to serialize PathCandidate: {error}"));
        let roundtripped: PathCandidate = serde_norway::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize PathCandidate: {error}"));

        // Assert
        assert_eq!(roundtripped, candidate);
        assert!(!roundtripped.source.security_group_rules[0].resolved);
    }
}
