//! Plain-text run summary (M3-T7). Pure: takes findings, returns a
//! `String`; the caller decides where it is written. The full report format
//! is Milestone 4's job — this is deliberately just counts, listings and a
//! way into Neo4j Browser.

use std::cmp::Reverse;

use aws_net_hound_core::domain::{Reachability, ReachabilityFinding};
use aws_net_hound_core::evaluate::{
    EvaluationLayer, EvaluationStep, IndeterminateReason, RuleRef, Verdict,
};

/// Max entries printed per section, so a badly scoped boundary cannot dump
/// thousands of lines into a terminal.
const LISTING_CAP: usize = 25;

const INDETERMINATE_NOTE: &str =
    "Indeterminate means the tool could not evaluate that path, not that the path is safe.";

/// Renders the run summary: counts, one line per reachable and per
/// indeterminate finding (each section capped at [`LISTING_CAP`]), then the
/// Neo4j Browser URL and a Cypher query for the listed source ENIs.
///
/// Findings are not stored in the graph, so the query selects the finding
/// *sources* (`ENI.id`) and their neighbours rather than finding nodes.
pub fn render_summary(findings: &[ReachabilityFinding], browser_url: &str) -> String {
    let mut reachable: Vec<&ReachabilityFinding> = findings
        .iter()
        .filter(|finding| matches!(finding.reachability, Reachability::Reachable))
        .collect();
    // Most severe first, so the cap drops the least severe. Stable sort.
    reachable.sort_by_key(|finding| Reverse(finding.severity));
    let indeterminate: Vec<&ReachabilityFinding> = findings
        .iter()
        .filter(|finding| matches!(finding.reachability, Reachability::Indeterminate { .. }))
        .collect();

    let mut lines = vec![
        format!("Paths reachable into boundary: {}", reachable.len()),
        format!("Paths indeterminate: {}", indeterminate.len()),
        format!("Paths evaluated: {}", findings.len()),
    ];

    if !reachable.is_empty() {
        lines.push(String::new());
        lines.push("Reachable paths:".to_string());
        push_capped(&mut lines, reachable.iter().map(|f| reachable_line(f)));
    }
    if !indeterminate.is_empty() {
        lines.push(String::new());
        lines.push("Indeterminate paths:".to_string());
        push_capped(
            &mut lines,
            indeterminate.iter().map(|f| indeterminate_line(f)),
        );
        lines.push(INDETERMINATE_NOTE.to_string());
    }

    lines.push(String::new());
    lines.push(format!("Neo4j Browser: {browser_url}"));

    let mut listed_sources: Vec<&str> = Vec::new();
    for finding in reachable
        .iter()
        .take(LISTING_CAP)
        .chain(indeterminate.iter().take(LISTING_CAP))
    {
        if !listed_sources.contains(&finding.source.as_str()) {
            listed_sources.push(&finding.source);
        }
    }
    if !listed_sources.is_empty() {
        lines.push("Cypher (listed source ENIs and their neighbours):".to_string());
        lines.push(cypher_query(&listed_sources));
    }

    lines.join("\n")
}

fn push_capped(lines: &mut Vec<String>, entries: impl ExactSizeIterator<Item = String>) {
    let remaining = entries.len().saturating_sub(LISTING_CAP);
    lines.extend(entries.take(LISTING_CAP));
    if remaining > 0 {
        lines.push(format!("  … and {remaining} more, see Neo4j Browser"));
    }
}

fn reachable_line(finding: &ReachabilityFinding) -> String {
    let evidence = finding
        .path_evidence
        .steps
        .iter()
        .map(step_evidence)
        .collect::<Vec<_>>()
        .join(" > ");
    // `Severity` is `#[non_exhaustive]` in another crate, so Debug is the
    // only rendering that cannot go stale when a variant is added.
    let severity = format!("{:?}", finding.severity).to_lowercase();
    format!(
        "  {} -> {} [{severity}] {evidence}",
        finding.source, finding.destination_boundary
    )
}

fn indeterminate_line(finding: &ReachabilityFinding) -> String {
    let layers = match &finding.reachability {
        Reachability::Indeterminate { layers } if !layers.is_empty() => layers
            .iter()
            .map(|layer| layer_name(*layer))
            .collect::<Vec<_>>()
            .join(", "),
        // Reachable/NotReachable never reach here; an empty list means the
        // evaluator named no layer, which must still read as unresolved.
        _ => "none reported".to_string(),
    };
    let unresolved: Vec<&str> = finding
        .path_evidence
        .steps
        .iter()
        .filter_map(unresolved_security_group)
        .collect();
    let detail = if unresolved.is_empty() {
        String::new()
    } else {
        format!("; unresolved: {}", unresolved.join(", "))
    };
    format!(
        "  {} -> {}  layers: {layers}{detail}",
        finding.source, finding.destination_boundary
    )
}

fn step_evidence(step: &EvaluationStep) -> String {
    let layer = layer_name(step.layer);
    // `Verdict`/`RuleRef` are `#[non_exhaustive]` in another crate; the
    // wildcard arms fall back to Debug rather than dropping the evidence.
    match &step.verdict {
        Verdict::Allowed { matched_by } => match matched_by {
            RuleRef::SecurityGroup {
                security_group_id,
                rule_index,
            } => format!("{layer}: {security_group_id} rule #{rule_index}"),
            RuleRef::NetworkAcl {
                network_acl_id,
                rule_number,
            } => format!("{layer}: {network_acl_id} rule {rule_number}"),
            other => format!("{layer}: {} {other:?}", step.resource_id),
        },
        other => format!("{layer}: {} {other:?}", step.resource_id),
    }
}

fn unresolved_security_group(step: &EvaluationStep) -> Option<&str> {
    match &step.verdict {
        Verdict::Indeterminate {
            reason: IndeterminateReason::UnresolvedReference { security_group_id },
        } => Some(security_group_id),
        // Every other verdict/reason carries no unresolved reference.
        _ => None,
    }
}

fn layer_name(layer: EvaluationLayer) -> &'static str {
    match layer {
        EvaluationLayer::SgEgress => "sg_egress",
        EvaluationLayer::NaclEgress => "nacl_egress",
        EvaluationLayer::NaclIngress => "nacl_ingress",
        EvaluationLayer::SgIngress => "sg_ingress",
    }
}

fn cypher_query(source_ids: &[&str]) -> String {
    // The query is pasted into a browser by a human; escape so an odd id
    // cannot break out of its string literal.
    let ids = source_ids
        .iter()
        .map(|id| format!("'{}'", id.replace('\\', "\\\\").replace('\'', "\\'")))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "MATCH (eni:ENI) WHERE eni.id IN [{ids}] \
         OPTIONAL MATCH (eni)-[edge]->(neighbour) RETURN eni, edge, neighbour"
    )
}

#[cfg(test)]
mod tests {
    use aws_net_hound_core::domain::Severity;
    use aws_net_hound_core::evaluate::PathEvidence;
    use pretty_assertions::assert_eq;

    use super::*;

    const URL: &str = "http://127.0.0.1:7474";

    fn finding(
        source: &str,
        severity: Severity,
        reachability: Reachability,
        steps: Vec<EvaluationStep>,
    ) -> ReachabilityFinding {
        ReachabilityFinding {
            computed_at: "2026-08-08T00:00:00Z".to_string(),
            source: source.to_string(),
            destination_boundary: "boundary-pci".to_string(),
            path_evidence: PathEvidence { steps },
            reachability,
            severity,
        }
    }

    fn allowed_by_sg(layer: EvaluationLayer, security_group_id: &str) -> EvaluationStep {
        EvaluationStep {
            layer,
            resource_id: security_group_id.to_string(),
            verdict: Verdict::Allowed {
                matched_by: RuleRef::SecurityGroup {
                    security_group_id: security_group_id.to_string(),
                    rule_index: 0,
                },
            },
        }
    }

    fn allowed_by_nacl(layer: EvaluationLayer, network_acl_id: &str) -> EvaluationStep {
        EvaluationStep {
            layer,
            resource_id: network_acl_id.to_string(),
            verdict: Verdict::Allowed {
                matched_by: RuleRef::NetworkAcl {
                    network_acl_id: network_acl_id.to_string(),
                    rule_number: 100,
                },
            },
        }
    }

    fn reachable(source: &str, severity: Severity) -> ReachabilityFinding {
        finding(
            source,
            severity,
            Reachability::Reachable,
            vec![
                allowed_by_sg(EvaluationLayer::SgEgress, "sg-1"),
                allowed_by_nacl(EvaluationLayer::NaclEgress, "acl-1"),
            ],
        )
    }

    fn indeterminate(source: &str) -> ReachabilityFinding {
        finding(
            source,
            Severity::Medium,
            Reachability::Indeterminate {
                layers: vec![EvaluationLayer::SgIngress],
            },
            vec![EvaluationStep {
                layer: EvaluationLayer::SgIngress,
                resource_id: "sg-2".to_string(),
                verdict: Verdict::Indeterminate {
                    reason: IndeterminateReason::UnresolvedReference {
                        security_group_id: "sg-9".to_string(),
                    },
                },
            }],
        )
    }

    fn not_reachable(source: &str) -> ReachabilityFinding {
        finding(
            source,
            Severity::Low,
            Reachability::NotReachable,
            Vec::new(),
        )
    }

    #[test]
    fn render_summary_no_findings_reports_zero_reachable() {
        // Arrange
        let findings: Vec<ReachabilityFinding> = Vec::new();

        // Act
        let summary = render_summary(&findings, URL);

        // Assert
        assert_eq!(
            summary,
            "Paths reachable into boundary: 0\n\
             Paths indeterminate: 0\n\
             Paths evaluated: 0\n\
             \n\
             Neo4j Browser: http://127.0.0.1:7474"
        );
    }

    #[test]
    fn render_summary_reachable_finding_includes_path_evidence() {
        // Arrange
        let findings = vec![reachable("eni-a", Severity::High)];

        // Act
        let summary = render_summary(&findings, URL);

        // Assert
        assert!(summary.contains(
            "  eni-a -> boundary-pci [high] sg_egress: sg-1 rule #0 > nacl_egress: acl-1 rule 100"
        ));
    }

    #[test]
    fn render_summary_indeterminate_finding_is_counted_separately_from_reachable() {
        // Arrange
        let findings = vec![
            reachable("eni-a", Severity::High),
            indeterminate("eni-b"),
            not_reachable("eni-c"),
        ];

        // Act
        let summary = render_summary(&findings, URL);

        // Assert
        assert!(summary.contains("Paths reachable into boundary: 1\n"));
        assert!(summary.contains("Paths indeterminate: 1\n"));
        assert!(summary.contains("Paths evaluated: 3\n"));
        assert!(summary.contains("  eni-b -> boundary-pci  layers: sg_ingress; unresolved: sg-9"));
    }

    #[test]
    fn render_summary_indeterminate_finding_states_it_is_not_safe() {
        // Arrange
        let findings = vec![indeterminate("eni-b")];

        // Act
        let summary = render_summary(&findings, URL);

        // Assert
        assert!(summary.contains(INDETERMINATE_NOTE));
        assert!(summary.contains("not that the path is safe"));
    }

    #[test]
    fn render_summary_includes_browser_url_and_cypher_query() {
        // Arrange
        let findings = vec![reachable("eni-a", Severity::High), indeterminate("eni-b")];

        // Act
        let summary = render_summary(&findings, URL);

        // Assert
        assert!(summary.contains("Neo4j Browser: http://127.0.0.1:7474"));
        assert!(summary.contains(
            "MATCH (eni:ENI) WHERE eni.id IN ['eni-a', 'eni-b'] \
             OPTIONAL MATCH (eni)-[edge]->(neighbour) RETURN eni, edge, neighbour"
        ));
    }

    #[test]
    fn render_summary_over_listing_cap_truncates_with_remaining_count() {
        // Arrange
        let findings: Vec<ReachabilityFinding> = (0..LISTING_CAP + 3)
            .map(|index| reachable(&format!("eni-{index}"), Severity::Low))
            .collect();

        // Act
        let summary = render_summary(&findings, URL);

        // Assert
        let listed = summary
            .lines()
            .filter(|line| line.starts_with("  eni-"))
            .count();
        assert_eq!(listed, LISTING_CAP);
        assert!(summary.contains("Paths reachable into boundary: 28\n"));
        assert!(summary.contains("  … and 3 more, see Neo4j Browser"));
    }

    #[test]
    fn render_summary_over_listing_cap_keeps_most_severe_findings() {
        // Arrange
        let mut findings: Vec<ReachabilityFinding> = (0..LISTING_CAP)
            .map(|index| reachable(&format!("eni-low-{index}"), Severity::Low))
            .collect();
        findings.push(reachable("eni-critical", Severity::Critical));

        // Act
        let summary = render_summary(&findings, URL);

        // Assert
        assert!(summary.contains("  eni-critical -> boundary-pci [critical]"));
        assert!(summary.contains("  … and 1 more, see Neo4j Browser"));
    }

    #[test]
    fn render_summary_cypher_query_escapes_single_quote_in_source() {
        // Arrange
        let findings = vec![reachable("eni-'quoted\\", Severity::High)];

        // Act
        let summary = render_summary(&findings, URL);

        // Assert
        assert!(summary.contains("IN ['eni-\\'quoted\\\\']"));
    }
}
