//! Types every report output format consumes. Three finding populations are
//! three separate fields with three separate types, so a renderer cannot
//! put an indeterminate finding in the "not reachable" table. No hash
//! collections appear anywhere in the model: every collection is an ordered
//! `Vec`, so the model itself is the ordering contract.

use serde::{Deserialize, Serialize};

use crate::domain::ReachabilityFinding;

/// The single root value every report output format consumes.
///
/// Each wrapper type must hold a finding whose
/// [`ReachabilityFinding::reachability`] matches its field. The model cannot
/// enforce that (deserialization bypasses constructors), so the aggregation
/// step that produces an `AuditReport` is the only place that partitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditReport {
    /// Run metadata and headline counts.
    pub summary: ReportSummary,
    /// Confirmed reachable into the regulated boundary.
    pub reachable: Vec<ReachableFinding>,
    /// Confirmed not reachable (evidence of coverage).
    pub not_reachable: Vec<NotReachableFinding>,
    /// No honest verdict could be reached; a reference was unresolved.
    pub indeterminate: Vec<IndeterminateFinding>,
}

/// A finding confirmed reachable into the regulated boundary.
///
/// Severity is read from `finding.severity`, never recomputed here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReachableFinding {
    /// The evaluator's finding, unmodified.
    pub finding: ReachabilityFinding,
}

/// A finding confirmed not reachable.
///
/// Deliberately not the same type as [`ReachableFinding`], so a renderer
/// cannot pass one where the other is expected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotReachableFinding {
    /// The evaluator's finding, unmodified.
    pub finding: ReachabilityFinding,
}

/// A finding with no verdict, because a reference could not be resolved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndeterminateFinding {
    /// The evaluator's finding, unmodified.
    pub finding: ReachabilityFinding,
    /// Why no verdict could be reached.
    pub cause: IndeterminateCause,
}

/// Why a finding is indeterminate.
///
/// A variant, not a message: the human sentence (for example "configure
/// read access to account 123456789012 to complete this analysis") is
/// produced by each renderer from the variant, so HTML and JSON never carry
/// two differently worded copies of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum IndeterminateCause {
    /// A rule references another AWS account that could not be read.
    UnresolvedCrossAccountReference {
        /// The account that was not readable, e.g. `123456789012`.
        account_id: String,
    },
    /// A rule references a security group that could not be resolved.
    UnresolvedSecurityGroupReference {
        /// The unresolved group, e.g. `sg-0example`.
        group_id: String,
    },
    /// A subnet's route table was not found, so routing is unknown.
    MissingRouteTable {
        /// The subnet without a known route table.
        subnet_id: String,
    },
    /// Any cause not covered by a dedicated variant.
    Other {
        /// Free-form detail for the operator.
        detail: String,
    },
}

/// Run metadata and headline numbers for an [`AuditReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// RFC 3339 UTC time the report was rendered.
    ///
    /// Render time, not verdict time, and the only non-deterministic field
    /// in the model: golden tests exclude this field and nothing else. Every
    /// per-finding timestamp is [`ReachabilityFinding::computed_at`], when
    /// the verdict was established.
    pub generated_at: String,
    /// What the audit covered.
    pub scope: ReportScope,
    /// Headline counts, stored so JSON consumers need not count arrays.
    pub counts: ReportCounts,
    /// Version of the tool that produced the report.
    ///
    /// Passed in by the caller (from `env!("CARGO_PKG_VERSION")` in the
    /// binary), not read by this library.
    pub tool_version: String,
}

/// What an audit covered, filled in by the caller from the ingest report.
///
/// A plain struct owned by `report`, so this module does not depend on the
/// ingest types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportScope {
    /// Audited AWS account ids.
    pub accounts: Vec<String>,
    /// Audited AWS regions.
    pub regions: Vec<String>,
    /// References that could not be resolved during ingest.
    pub unresolved_reference_count: usize,
}

/// Number of findings in each population.
///
/// The serialized field names are a published contract (see the report
/// format documentation): renaming one is a breaking change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportCounts {
    /// Length of [`AuditReport::reachable`].
    pub reachable: usize,
    /// Length of [`AuditReport::not_reachable`].
    pub not_reachable: usize,
    /// Length of [`AuditReport::indeterminate`].
    pub indeterminate: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Reachability, Severity};
    use crate::evaluate::path::PathEvidence;
    use pretty_assertions::assert_eq;

    fn sample_finding(reachability: Reachability) -> ReachabilityFinding {
        ReachabilityFinding {
            computed_at: "2026-08-08T00:00:00Z".to_string(),
            source: "eni-0example".to_string(),
            destination_boundary: "boundary-pci-prod".to_string(),
            path_evidence: PathEvidence { steps: Vec::new() },
            reachability,
            severity: Severity::High,
        }
    }

    #[test]
    fn audit_report_serializes_and_deserializes_to_equal_value() {
        // Arrange
        let report = AuditReport {
            summary: ReportSummary {
                generated_at: "2026-08-09T00:00:00Z".to_string(),
                scope: ReportScope {
                    accounts: vec!["123456789012".to_string()],
                    regions: vec!["us-east-1".to_string()],
                    unresolved_reference_count: 1,
                },
                counts: ReportCounts {
                    reachable: 1,
                    not_reachable: 1,
                    indeterminate: 1,
                },
                tool_version: "0.1.0".to_string(),
            },
            reachable: vec![ReachableFinding {
                finding: sample_finding(Reachability::Reachable),
            }],
            not_reachable: vec![NotReachableFinding {
                finding: sample_finding(Reachability::NotReachable),
            }],
            indeterminate: vec![IndeterminateFinding {
                finding: sample_finding(Reachability::Indeterminate { layers: Vec::new() }),
                cause: IndeterminateCause::UnresolvedSecurityGroupReference {
                    group_id: "sg-0example".to_string(),
                },
            }],
        };

        // Act
        let serialized = serde_json::to_string(&report)
            .unwrap_or_else(|error| panic!("failed to serialize AuditReport: {error}"));
        let roundtripped: AuditReport = serde_json::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize AuditReport: {error}"));

        // Assert
        assert_eq!(roundtripped, report);
    }

    #[test]
    fn indeterminate_cause_unresolved_cross_account_round_trips_account_id() {
        // Arrange
        let cause = IndeterminateCause::UnresolvedCrossAccountReference {
            account_id: "123456789012".to_string(),
        };

        // Act
        let serialized = serde_json::to_string(&cause)
            .unwrap_or_else(|error| panic!("failed to serialize IndeterminateCause: {error}"));
        let roundtripped: IndeterminateCause = serde_json::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize IndeterminateCause: {error}"));

        // Assert
        assert_eq!(roundtripped, cause);
    }

    #[test]
    fn report_counts_serialize_with_stable_field_names() {
        // Arrange
        let counts = ReportCounts {
            reachable: 2,
            not_reachable: 1,
            indeterminate: 3,
        };

        // Act
        let serialized = serde_json::to_string(&counts)
            .unwrap_or_else(|error| panic!("failed to serialize ReportCounts: {error}"));

        // Assert
        assert_eq!(
            serialized,
            r#"{"reachable":2,"not_reachable":1,"indeterminate":3}"#
        );
    }
}
