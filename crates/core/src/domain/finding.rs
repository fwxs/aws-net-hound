//! Reachability finding domain types, emitted by the Milestone 2 evaluator
//! and rendered by Milestone 4. Rendering (turning `path_evidence` into
//! human-readable text) is out of scope here — this module only carries
//! structured evidence.

use serde::{Deserialize, Serialize};

use crate::evaluate::path::{EvaluationLayer, PathEvidence};

/// Severity of a reachability finding.
///
/// `Ord` is derived from declaration order — `Low < Medium < High <
/// Critical` — and pinned by
/// `tests::severity_ord_ranks_in_declared_order`. A new variant must be
/// inserted at its intended rank, not appended, or that test catches the
/// inversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// The reachability outcome an [`crate::ports::Evaluator`] reached for one
/// [`crate::evaluate::path::PathCandidate`].
///
/// Not a `bool` plus an `indeterminate: bool` flag: that shape permits the
/// meaningless state "reachable and indeterminate". An indeterminate
/// verdict on any layer must propagate here rather than collapse into
/// `NotReachable` — see `RuleIntersectionEvaluator::combine_verdicts`'s doc
/// comment for why `Denied` still takes precedence over `Indeterminate`
/// when both occur across different layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Reachability {
    /// Every consulted layer allowed the traffic.
    Reachable,
    /// At least one layer denied the traffic; evaluation short-circuited
    /// there, so `path_evidence` ends at the deciding step.
    ///
    /// Distinct from "no route existed to evaluate" (also `NotReachable`
    /// today, when [`crate::evaluate::path::PathCandidate::route_exists`]
    /// was `false`): the two causes are only distinguishable by checking
    /// whether `path_evidence.steps` is empty (no-route case) or non-empty
    /// ending in a `Denied` verdict (explicit-deny case) — see
    /// `RuleIntersectionEvaluator::evaluate_candidate`'s no-route
    /// early-return in `engine.rs`. If a consumer ever needs to
    /// distinguish these operationally, split this into dedicated variants
    /// rather than growing a side-channel flag; `Reachability` is
    /// `#[non_exhaustive]` specifically to allow that later.
    NotReachable,
    /// No layer denied the traffic, but at least one layer could not reach
    /// a definite verdict (e.g. an unresolved cross-account security group
    /// reference). Names which layer(s) so a finding is actionable without
    /// re-querying the graph.
    Indeterminate { layers: Vec<EvaluationLayer> },
}

/// A computed reachability finding: a source was evaluated against a
/// regulated boundary, with the evidentiary path and its severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityFinding {
    /// UTC timestamp, ISO-8601 (RFC 3339), of when this finding was
    /// computed.
    pub computed_at: String,
    /// Unique key of the source node the reachability check started from
    /// (e.g. an `ENI` id).
    pub source: String,
    /// `RegulatedBoundary.id` this finding correlates against — matched by
    /// key, not graph traversal, per `schema.md`.
    pub destination_boundary: String,
    /// Structured evidence of the path that produced this finding.
    pub path_evidence: PathEvidence,
    /// The reachability outcome this finding represents.
    pub reachability: Reachability,
    /// How severe this finding is.
    pub severity: Severity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn reachability_finding_serializes_structured_path_evidence() {
        // Arrange
        use crate::evaluate::path::{EvaluationLayer, EvaluationStep};
        use crate::evaluate::{RuleRef, Verdict};

        let finding = ReachabilityFinding {
            computed_at: "2026-08-08T00:00:00Z".to_string(),
            source: "eni-0example".to_string(),
            destination_boundary: "boundary-pci-prod".to_string(),
            path_evidence: PathEvidence {
                steps: vec![EvaluationStep {
                    layer: EvaluationLayer::SgEgress,
                    resource_id: "sg-0example".to_string(),
                    verdict: Verdict::Allowed {
                        matched_by: RuleRef::SecurityGroup {
                            security_group_id: "sg-0example".to_string(),
                            rule_index: 0,
                        },
                    },
                }],
            },
            reachability: Reachability::Reachable,
            severity: Severity::High,
        };

        // Act
        let serialized = serde_norway::to_string(&finding)
            .unwrap_or_else(|error| panic!("failed to serialize ReachabilityFinding: {error}"));
        let roundtripped: ReachabilityFinding = serde_norway::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize ReachabilityFinding: {error}"));

        // Assert
        assert_eq!(roundtripped, finding);
    }

    #[test]
    fn reachability_indeterminate_variant_round_trips_with_layers() {
        // Arrange
        let reachability = Reachability::Indeterminate {
            layers: vec![EvaluationLayer::SgEgress, EvaluationLayer::NaclIngress],
        };

        // Act
        let serialized = serde_norway::to_string(&reachability)
            .unwrap_or_else(|error| panic!("failed to serialize Reachability: {error}"));
        let roundtripped: Reachability = serde_norway::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize Reachability: {error}"));

        // Assert
        assert_eq!(roundtripped, reachability);
    }

    #[test]
    fn severity_ord_ranks_in_declared_order() {
        // Arrange
        let ascending = [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let mut shuffled = [
            Severity::Critical,
            Severity::Low,
            Severity::High,
            Severity::Medium,
        ];

        // Act
        shuffled.sort();

        // Assert
        assert_eq!(shuffled, ascending);
    }
}
