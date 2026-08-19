//! Reachability finding domain types, emitted by the Milestone 2 evaluator
//! and rendered by Milestone 4. Rendering (turning `path_evidence` into
//! human-readable text) is out of scope here — this module only carries
//! structured evidence.

use serde::{Deserialize, Serialize};

use crate::evaluate::path::PathEvidence;

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

/// A computed reachability finding: a source was found to reach a
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
