//! Types every report output format consumes. Three finding populations are
//! three separate fields with three separate types, so a renderer cannot
//! put an indeterminate finding in the "not reachable" table. No hash
//! collections appear anywhere in the model: every collection is an ordered
//! `Vec` or `BTreeSet`, so the model itself is the ordering contract.
//!
//! The model enforces its own invariants. A finding can only enter the
//! population its `reachability` belongs to, counts are computed rather
//! than supplied, and deserialization re-runs the same checks, so a report
//! read back from disk cannot disagree with itself. `AuditReport::new` keeps
//! the order it is given; sorting the populations is the job of the
//! aggregation step (`ReportBuilder`, issue #18).
//!
//! # Determinism
//!
//! Two runs over unchanged infrastructure differ in exactly two kinds of
//! field: [`ReportSummary::generated_at`] (render time) and every
//! [`ReachabilityFinding::computed_at`] (verdict time, stamped by the
//! evaluator). Golden tests must mask both.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset};

use crate::domain::{Reachability, ReachabilityFinding};
use crate::error::ReportModelError;
use crate::evaluate::path::EvaluationLayer;

/// Name of a finding's own reachability, for error messages.
fn reachability_label(reachability: &Reachability) -> &'static str {
    match reachability {
        Reachability::Reachable => "reachable",
        Reachability::NotReachable => "not_reachable",
        Reachability::Indeterminate { .. } => "indeterminate",
    }
}

/// Build the error for a finding placed in the wrong population.
fn reachability_mismatch(
    population: &'static str,
    finding: &ReachabilityFinding,
) -> ReportModelError {
    ReportModelError::ReachabilityMismatch {
        population,
        actual: reachability_label(&finding.reachability),
        finding_source: finding.source.clone(),
    }
}

/// The single root value every report output format consumes.
///
/// Fields are private so a population cannot be edited after construction
/// and drift from the counts in the summary. Build one with
/// [`AuditReport::new`]; read it through the accessors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "AuditReportWire")]
pub struct AuditReport {
    summary: ReportSummary,
    reachable: Vec<ReachableFinding>,
    not_reachable: Vec<NotReachableFinding>,
    indeterminate: Vec<IndeterminateFinding>,
}

impl AuditReport {
    /// Assemble a report from already-validated parts.
    ///
    /// The counts are computed from the populations, and `generated_at` is
    /// normalized to UTC so it always serializes with a `Z` suffix. The
    /// populations keep the order given.
    pub fn new(
        scope: ReportScope,
        tool_version: impl Into<String>,
        generated_at: OffsetDateTime,
        reachable: Vec<ReachableFinding>,
        not_reachable: Vec<NotReachableFinding>,
        indeterminate: Vec<IndeterminateFinding>,
    ) -> Self {
        let counts = ReportCounts::from_populations(&reachable, &not_reachable, &indeterminate);
        Self {
            summary: ReportSummary {
                generated_at: generated_at.to_offset(UtcOffset::UTC),
                scope,
                counts,
                tool_version: tool_version.into(),
            },
            reachable,
            not_reachable,
            indeterminate,
        }
    }

    /// Run metadata and headline counts.
    pub fn summary(&self) -> &ReportSummary {
        &self.summary
    }

    /// Findings confirmed reachable into the regulated boundary.
    pub fn reachable(&self) -> &[ReachableFinding] {
        &self.reachable
    }

    /// Findings confirmed not reachable (evidence of coverage).
    pub fn not_reachable(&self) -> &[NotReachableFinding] {
        &self.not_reachable
    }

    /// Findings with no honest verdict because a reference was unresolved.
    pub fn indeterminate(&self) -> &[IndeterminateFinding] {
        &self.indeterminate
    }
}

/// Deserialization shape of [`AuditReport`], checked in [`TryFrom`].
#[derive(Deserialize)]
struct AuditReportWire {
    summary: ReportSummary,
    reachable: Vec<ReachableFinding>,
    not_reachable: Vec<NotReachableFinding>,
    indeterminate: Vec<IndeterminateFinding>,
}

impl TryFrom<AuditReportWire> for AuditReport {
    type Error = ReportModelError;

    fn try_from(wire: AuditReportWire) -> Result<Self, Self::Error> {
        let actual = ReportCounts::from_populations(
            &wire.reachable,
            &wire.not_reachable,
            &wire.indeterminate,
        );
        let declared = &wire.summary.counts;
        for (population, declared_count, actual_count) in [
            ("reachable", declared.reachable, actual.reachable),
            (
                "not_reachable",
                declared.not_reachable,
                actual.not_reachable,
            ),
            (
                "indeterminate",
                declared.indeterminate,
                actual.indeterminate,
            ),
        ] {
            if declared_count != actual_count {
                return Err(ReportModelError::CountsMismatch {
                    population,
                    declared: declared_count,
                    actual: actual_count,
                });
            }
        }

        let mut summary = wire.summary;
        summary.generated_at = summary.generated_at.to_offset(UtcOffset::UTC);
        Ok(Self {
            summary,
            reachable: wire.reachable,
            not_reachable: wire.not_reachable,
            indeterminate: wire.indeterminate,
        })
    }
}

/// Deserialization shape shared by the two single-finding wrappers.
#[derive(Deserialize)]
struct FindingWire {
    finding: ReachabilityFinding,
}

/// A finding confirmed reachable into the regulated boundary.
///
/// Severity is read from `finding.severity`, never recomputed here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "FindingWire")]
pub struct ReachableFinding {
    finding: ReachabilityFinding,
}

impl ReachableFinding {
    /// Wrap a finding, rejecting one whose `reachability` is not
    /// [`Reachability::Reachable`].
    ///
    /// # Errors
    ///
    /// Returns [`ReportModelError::ReachabilityMismatch`] when the finding
    /// belongs to another population.
    pub fn new(finding: ReachabilityFinding) -> Result<Self, ReportModelError> {
        if matches!(finding.reachability, Reachability::Reachable) {
            Ok(Self { finding })
        } else {
            Err(reachability_mismatch("reachable", &finding))
        }
    }

    /// The evaluator's finding, unmodified.
    pub fn finding(&self) -> &ReachabilityFinding {
        &self.finding
    }
}

impl TryFrom<FindingWire> for ReachableFinding {
    type Error = ReportModelError;

    fn try_from(wire: FindingWire) -> Result<Self, Self::Error> {
        Self::new(wire.finding)
    }
}

/// A finding confirmed not reachable.
///
/// Deliberately not the same type as [`ReachableFinding`], so a renderer
/// cannot pass one where the other is expected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "FindingWire")]
pub struct NotReachableFinding {
    finding: ReachabilityFinding,
}

impl NotReachableFinding {
    /// Wrap a finding, rejecting one whose `reachability` is not
    /// [`Reachability::NotReachable`].
    ///
    /// # Errors
    ///
    /// Returns [`ReportModelError::ReachabilityMismatch`] when the finding
    /// belongs to another population.
    pub fn new(finding: ReachabilityFinding) -> Result<Self, ReportModelError> {
        if matches!(finding.reachability, Reachability::NotReachable) {
            Ok(Self { finding })
        } else {
            Err(reachability_mismatch("not_reachable", &finding))
        }
    }

    /// The evaluator's finding, unmodified.
    pub fn finding(&self) -> &ReachabilityFinding {
        &self.finding
    }
}

impl TryFrom<FindingWire> for NotReachableFinding {
    type Error = ReportModelError;

    fn try_from(wire: FindingWire) -> Result<Self, Self::Error> {
        Self::new(wire.finding)
    }
}

/// A finding with no verdict, because a reference could not be resolved.
///
/// Carries one cause per layer the evaluator could not decide, so the
/// operator sees every access gap rather than only the first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "IndeterminateWire")]
pub struct IndeterminateFinding {
    finding: ReachabilityFinding,
    causes: Vec<LayerCause>,
}

impl IndeterminateFinding {
    /// Wrap a finding with the cause of each indeterminate layer.
    ///
    /// The causes are sorted into evaluation order, so the result does not
    /// depend on the order they were supplied in.
    ///
    /// # Errors
    ///
    /// Returns [`ReportModelError::ReachabilityMismatch`] when the finding
    /// is not [`Reachability::Indeterminate`], and
    /// [`ReportModelError::CauseLayerMismatch`] unless the causes cover
    /// exactly the layers the finding lists, once each.
    pub fn new(
        finding: ReachabilityFinding,
        mut causes: Vec<LayerCause>,
    ) -> Result<Self, ReportModelError> {
        let Reachability::Indeterminate { layers } = &finding.reachability else {
            return Err(reachability_mismatch("indeterminate", &finding));
        };

        let expected: BTreeSet<EvaluationLayer> = layers.iter().copied().collect();
        let covered: BTreeSet<EvaluationLayer> = causes.iter().map(|cause| cause.layer).collect();
        // A length difference means a layer was given two causes.
        if covered != expected || covered.len() != causes.len() {
            return Err(ReportModelError::CauseLayerMismatch {
                finding_source: finding.source.clone(),
            });
        }

        causes.sort_by_key(|cause| cause.layer);
        Ok(Self { finding, causes })
    }

    /// The evaluator's finding, unmodified.
    pub fn finding(&self) -> &ReachabilityFinding {
        &self.finding
    }

    /// Why each indeterminate layer could not be decided, in evaluation
    /// order.
    pub fn causes(&self) -> &[LayerCause] {
        &self.causes
    }
}

/// Deserialization shape of [`IndeterminateFinding`].
#[derive(Deserialize)]
struct IndeterminateWire {
    finding: ReachabilityFinding,
    causes: Vec<LayerCause>,
}

impl TryFrom<IndeterminateWire> for IndeterminateFinding {
    type Error = ReportModelError;

    fn try_from(wire: IndeterminateWire) -> Result<Self, Self::Error> {
        Self::new(wire.finding, wire.causes)
    }
}

/// The reason one evaluation layer could not reach a verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayerCause {
    /// The layer that stayed undecided.
    pub layer: EvaluationLayer,
    /// Why it stayed undecided.
    pub cause: IndeterminateCause,
}

/// Why a layer is indeterminate.
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
    ///
    /// Renderers print `detail` verbatim and cannot offer an action for it:
    /// prefer adding a dedicated variant over using this one.
    Other {
        /// Free-form detail for the operator.
        detail: String,
    },
}

/// Run metadata and headline numbers for an [`AuditReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// UTC time the report was rendered, serialized as RFC 3339 with a `Z`
    /// suffix.
    ///
    /// Render time, not verdict time. It is one of two kinds of
    /// non-deterministic field in a report: the other is
    /// [`ReachabilityFinding::computed_at`], the time each verdict was
    /// established, which the evaluator stamps on every finding. Golden
    /// tests mask both.
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    /// What the audit covered.
    pub scope: ReportScope,
    /// Headline counts, computed by [`AuditReport::new`] so they always
    /// match the populations. Stored so JSON consumers need not count
    /// arrays.
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
/// ingest types. Accounts and regions are sets, so they are sorted and free
/// of duplicates by construction and identical audits serialize identically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ReportScopeWire")]
pub struct ReportScope {
    accounts: BTreeSet<String>,
    regions: BTreeSet<String>,
    unresolved_reference_count: usize,
}

impl ReportScope {
    /// Build a scope from the audited accounts and regions.
    ///
    /// `unresolved_reference_count` is an ingest-level figure: how many
    /// references ingest could not resolve. It is independent of the number
    /// of indeterminate findings, because an unresolved reference on a rule
    /// that lies on no evaluated path produces no finding at all.
    ///
    /// # Errors
    ///
    /// Returns [`ReportModelError::EmptyScope`] when either list is empty:
    /// a scope that covers nothing would yield a clean-looking report that
    /// audited nothing.
    pub fn new(
        accounts: impl IntoIterator<Item = String>,
        regions: impl IntoIterator<Item = String>,
        unresolved_reference_count: usize,
    ) -> Result<Self, ReportModelError> {
        let accounts: BTreeSet<String> = accounts.into_iter().collect();
        let regions: BTreeSet<String> = regions.into_iter().collect();
        if accounts.is_empty() {
            return Err(ReportModelError::EmptyScope { field: "accounts" });
        }
        if regions.is_empty() {
            return Err(ReportModelError::EmptyScope { field: "regions" });
        }
        Ok(Self {
            accounts,
            regions,
            unresolved_reference_count,
        })
    }

    /// Audited AWS account ids, sorted.
    pub fn accounts(&self) -> &BTreeSet<String> {
        &self.accounts
    }

    /// Audited AWS regions, sorted.
    pub fn regions(&self) -> &BTreeSet<String> {
        &self.regions
    }

    /// References ingest could not resolve, supplied by the caller from the
    /// ingest report. Not derived from, and not checked against, the
    /// indeterminate findings.
    pub fn unresolved_reference_count(&self) -> usize {
        self.unresolved_reference_count
    }
}

/// Deserialization shape of [`ReportScope`].
#[derive(Deserialize)]
struct ReportScopeWire {
    accounts: BTreeSet<String>,
    regions: BTreeSet<String>,
    unresolved_reference_count: usize,
}

impl TryFrom<ReportScopeWire> for ReportScope {
    type Error = ReportModelError;

    fn try_from(wire: ReportScopeWire) -> Result<Self, Self::Error> {
        Self::new(wire.accounts, wire.regions, wire.unresolved_reference_count)
    }
}

/// Number of findings in each population.
///
/// Computed by [`AuditReport::new`] and re-checked on deserialization; it
/// cannot be attached to a report by hand. The serialized field names are a
/// published contract (to be documented in `crates/core/docs/report.md`,
/// issue #24): renaming one is a breaking change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportCounts {
    /// Length of [`AuditReport::reachable`].
    pub reachable: usize,
    /// Length of [`AuditReport::not_reachable`].
    pub not_reachable: usize,
    /// Length of [`AuditReport::indeterminate`].
    pub indeterminate: usize,
}

impl ReportCounts {
    /// Count the findings in each population.
    pub(crate) fn from_populations(
        reachable: &[ReachableFinding],
        not_reachable: &[NotReachableFinding],
        indeterminate: &[IndeterminateFinding],
    ) -> Self {
        Self {
            reachable: reachable.len(),
            not_reachable: not_reachable.len(),
            indeterminate: indeterminate.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;
    use crate::evaluate::path::PathEvidence;
    use pretty_assertions::assert_eq;
    use serde_json::json;

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

    fn sample_scope() -> ReportScope {
        ReportScope::new(["123456789012".to_string()], ["us-east-1".to_string()], 1)
            .unwrap_or_else(|error| panic!("failed to build ReportScope: {error}"))
    }

    fn sg_cause(layer: EvaluationLayer) -> LayerCause {
        LayerCause {
            layer,
            cause: IndeterminateCause::UnresolvedSecurityGroupReference {
                group_id: "sg-0example".to_string(),
            },
        }
    }

    fn sample_indeterminate(layers: Vec<EvaluationLayer>) -> IndeterminateFinding {
        let causes = layers.iter().copied().map(sg_cause).collect();
        IndeterminateFinding::new(
            sample_finding(Reachability::Indeterminate { layers }),
            causes,
        )
        .unwrap_or_else(|error| panic!("failed to build IndeterminateFinding: {error}"))
    }

    fn sample_report() -> AuditReport {
        let reachable = ReachableFinding::new(sample_finding(Reachability::Reachable))
            .unwrap_or_else(|error| panic!("failed to build ReachableFinding: {error}"));
        let not_reachable = NotReachableFinding::new(sample_finding(Reachability::NotReachable))
            .unwrap_or_else(|error| panic!("failed to build NotReachableFinding: {error}"));

        AuditReport::new(
            sample_scope(),
            "0.1.0",
            OffsetDateTime::UNIX_EPOCH,
            vec![reachable],
            vec![not_reachable],
            vec![sample_indeterminate(vec![EvaluationLayer::SgEgress])],
        )
    }

    #[test]
    fn audit_report_serializes_and_deserializes_to_equal_value() {
        // Arrange
        let report = sample_report();

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

    #[test]
    fn reachable_finding_new_with_not_reachable_returns_mismatch() {
        // Arrange
        let finding = sample_finding(Reachability::NotReachable);

        // Act
        let result = ReachableFinding::new(finding);

        // Assert
        assert!(matches!(
            result,
            Err(ReportModelError::ReachabilityMismatch {
                population: "reachable",
                actual: "not_reachable",
                ..
            })
        ));
    }

    #[test]
    fn not_reachable_finding_new_with_reachable_returns_mismatch() {
        // Arrange
        let finding = sample_finding(Reachability::Reachable);

        // Act
        let result = NotReachableFinding::new(finding);

        // Assert
        assert!(matches!(
            result,
            Err(ReportModelError::ReachabilityMismatch {
                population: "not_reachable",
                actual: "reachable",
                ..
            })
        ));
    }

    #[test]
    fn indeterminate_finding_new_with_missing_layer_cause_returns_mismatch() {
        // Arrange
        let finding = sample_finding(Reachability::Indeterminate {
            layers: vec![EvaluationLayer::SgEgress, EvaluationLayer::NaclIngress],
        });
        let causes = vec![sg_cause(EvaluationLayer::SgEgress)];

        // Act
        let result = IndeterminateFinding::new(finding, causes);

        // Assert
        assert!(matches!(
            result,
            Err(ReportModelError::CauseLayerMismatch { .. })
        ));
    }

    #[test]
    fn indeterminate_finding_new_with_duplicate_layer_cause_returns_mismatch() {
        // Arrange
        let finding = sample_finding(Reachability::Indeterminate {
            layers: vec![EvaluationLayer::SgEgress],
        });
        let causes = vec![
            sg_cause(EvaluationLayer::SgEgress),
            sg_cause(EvaluationLayer::SgEgress),
        ];

        // Act
        let result = IndeterminateFinding::new(finding, causes);

        // Assert
        assert!(matches!(
            result,
            Err(ReportModelError::CauseLayerMismatch { .. })
        ));
    }

    #[test]
    fn indeterminate_finding_new_sorts_causes_by_layer() {
        // Arrange
        let finding = sample_finding(Reachability::Indeterminate {
            layers: vec![EvaluationLayer::NaclIngress, EvaluationLayer::SgEgress],
        });
        let causes = vec![
            sg_cause(EvaluationLayer::NaclIngress),
            sg_cause(EvaluationLayer::SgEgress),
        ];

        // Act
        let indeterminate = IndeterminateFinding::new(finding, causes)
            .unwrap_or_else(|error| panic!("failed to build IndeterminateFinding: {error}"));
        let layers: Vec<EvaluationLayer> = indeterminate
            .causes()
            .iter()
            .map(|cause| cause.layer)
            .collect();

        // Assert
        assert_eq!(
            layers,
            vec![EvaluationLayer::SgEgress, EvaluationLayer::NaclIngress]
        );
    }

    #[test]
    fn audit_report_new_computes_counts_from_populations() {
        // Arrange
        let report = sample_report();

        // Act
        let counts = &report.summary().counts;

        // Assert
        assert_eq!(
            counts,
            &ReportCounts {
                reachable: 1,
                not_reachable: 1,
                indeterminate: 1,
            }
        );
    }

    #[test]
    fn audit_report_deserialize_with_wrong_counts_returns_error() {
        // Arrange
        let mut value = serde_json::to_value(sample_report())
            .unwrap_or_else(|error| panic!("failed to serialize AuditReport: {error}"));
        value["summary"]["counts"]["reachable"] = json!(5);

        // Act
        let result = serde_json::from_value::<AuditReport>(value);

        // Assert
        let message = result.err().map(|error| error.to_string());
        assert_eq!(
            message.as_deref(),
            Some("report declares 5 reachable findings but holds 1")
        );
    }

    #[test]
    fn audit_report_deserialize_with_misplaced_finding_returns_error() {
        // Arrange
        let mut value = serde_json::to_value(sample_report())
            .unwrap_or_else(|error| panic!("failed to serialize AuditReport: {error}"));
        value["not_reachable"] = value["reachable"].clone();

        // Act
        let result = serde_json::from_value::<AuditReport>(value);

        // Assert
        let message = result.err().map(|error| error.to_string());
        assert_eq!(
            message.as_deref(),
            Some(
                "finding from `eni-0example` is reachable but was placed in the not_reachable \
                 population"
            )
        );
    }

    #[test]
    fn report_scope_new_sorts_and_deduplicates_entries() {
        // Arrange
        let accounts = ["222222222222", "111111111111", "222222222222"].map(String::from);
        let regions = ["us-east-1".to_string()];

        // Act
        let scope = ReportScope::new(accounts, regions, 0)
            .unwrap_or_else(|error| panic!("failed to build ReportScope: {error}"));
        let ordered: Vec<&str> = scope.accounts().iter().map(String::as_str).collect();

        // Assert
        assert_eq!(ordered, vec!["111111111111", "222222222222"]);
    }

    #[test]
    fn report_scope_new_with_empty_accounts_returns_error() {
        // Arrange
        let accounts: [String; 0] = [];
        let regions = ["us-east-1".to_string()];

        // Act
        let result = ReportScope::new(accounts, regions, 0);

        // Assert
        assert!(matches!(
            result,
            Err(ReportModelError::EmptyScope { field: "accounts" })
        ));
    }

    #[test]
    fn audit_report_new_serializes_generated_at_as_utc_rfc3339() {
        // Arrange
        let plus_two_hours = UtcOffset::from_hms(2, 0, 0)
            .unwrap_or_else(|error| panic!("failed to build UtcOffset: {error}"));
        let report = AuditReport::new(
            sample_scope(),
            "0.1.0",
            OffsetDateTime::UNIX_EPOCH.to_offset(plus_two_hours),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        // Act
        let value = serde_json::to_value(&report)
            .unwrap_or_else(|error| panic!("failed to serialize AuditReport: {error}"));

        // Assert
        assert_eq!(
            value["summary"]["generated_at"].as_str(),
            Some("1970-01-01T00:00:00Z")
        );
    }
}
