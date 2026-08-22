//! Four-layer SG/NACL intersection (M2-T6) — the function the whole
//! project exists to provide. Combines the per-layer evaluators from
//! [`crate::evaluate::sg`] (M2-T2) and [`crate::evaluate::nacl`] (M2-T3)
//! into one [`ReachabilityFinding`], never mentioning Neo4j or any driver
//! type (see [`Evaluator`]'s contract).

use tracing::{debug, info};

use crate::domain::{Reachability, ReachabilityFinding, Severity};
use crate::error::EvaluationError;
use crate::evaluate::nacl::{evaluate_nacl_egress, evaluate_nacl_ingress};
use crate::evaluate::path::{EvaluationLayer, EvaluationStep, PathCandidate, PathEvidence};
use crate::evaluate::sg::{evaluate_sg_egress, evaluate_sg_ingress, PeerIdentity};
use crate::evaluate::Verdict;
use crate::ports::{BoxFuture, Evaluator};

/// Intersects a [`PathCandidate`]'s four rule layers (SG egress, NACL
/// egress, NACL ingress, SG ingress) into one [`ReachabilityFinding`].
///
/// A unit struct, not a configurable one: there is no state and nothing to
/// configure — it exists solely to satisfy [`Evaluator`].
pub struct RuleIntersectionEvaluator;

impl Evaluator for RuleIntersectionEvaluator {
    fn evaluate(
        &self,
        candidate: &PathCandidate,
    ) -> BoxFuture<'_, Result<ReachabilityFinding, EvaluationError>> {
        let finding = evaluate_candidate(candidate);
        // No I/O happens here: the future resolves immediately. `async
        // move` is used (rather than `std::future::ready`) to match every
        // other `Evaluator`/`GraphWriter`/`Resolver` implementation's shape
        // in this codebase.
        Box::pin(async move { Ok(finding) })
    }
}

fn evaluate_candidate(candidate: &PathCandidate) -> ReachabilityFinding {
    if !candidate.route_exists {
        // No route: nothing to evaluate at any layer. Evidence is
        // deliberately empty (no SG/NACL resource decided this) rather than
        // a synthetic step, mirroring how `nacl.rs` never synthesizes a
        // fake rule for the implicit `*` deny. `combine_verdicts` folds an
        // empty step list to `Reachable` (vacuously "no layer denied"),
        // which is wrong here — there is no path to intersect at all — so
        // this case bypasses `combine_verdicts` entirely.
        return finish_with(
            candidate,
            PathEvidence { steps: Vec::new() },
            Reachability::NotReachable,
        );
    }

    let mut steps = Vec::with_capacity(4);

    let destination_peer = PeerIdentity {
        security_group_ids: &candidate.destination.peer_security_group_ids,
    };
    let sg_egress_verdict = evaluate_sg_egress(
        &candidate.source.eni_id,
        &candidate.source.security_group_rules,
        &candidate.traffic,
        &destination_peer,
    );
    log_layer(
        EvaluationLayer::SgEgress,
        &candidate.source.eni_id,
        &sg_egress_verdict,
    );
    let sg_egress_allowed = matches!(sg_egress_verdict, Verdict::Allowed { .. });
    steps.push(EvaluationStep {
        layer: EvaluationLayer::SgEgress,
        resource_id: candidate.source.eni_id.clone(),
        verdict: sg_egress_verdict,
    });
    if !sg_egress_allowed {
        return finish(candidate, steps);
    }

    let nacl_egress_verdict = evaluate_nacl_egress(
        &candidate.source.subnet_id,
        &candidate.source.nacl_rules,
        &candidate.traffic,
    );
    log_layer(
        EvaluationLayer::NaclEgress,
        &candidate.source.subnet_id,
        &nacl_egress_verdict,
    );
    let nacl_egress_allowed = matches!(nacl_egress_verdict, Verdict::Allowed { .. });
    steps.push(EvaluationStep {
        layer: EvaluationLayer::NaclEgress,
        resource_id: candidate.source.subnet_id.clone(),
        verdict: nacl_egress_verdict,
    });
    if !nacl_egress_allowed {
        return finish(candidate, steps);
    }

    let nacl_ingress_verdict = evaluate_nacl_ingress(
        &candidate.destination.subnet_id,
        &candidate.destination.nacl_rules,
        &candidate.traffic,
    );
    log_layer(
        EvaluationLayer::NaclIngress,
        &candidate.destination.subnet_id,
        &nacl_ingress_verdict,
    );
    let nacl_ingress_allowed = matches!(nacl_ingress_verdict, Verdict::Allowed { .. });
    steps.push(EvaluationStep {
        layer: EvaluationLayer::NaclIngress,
        resource_id: candidate.destination.subnet_id.clone(),
        verdict: nacl_ingress_verdict,
    });
    if !nacl_ingress_allowed {
        return finish(candidate, steps);
    }

    let source_peer = PeerIdentity {
        security_group_ids: &candidate.source.peer_security_group_ids,
    };
    let sg_ingress_verdict = evaluate_sg_ingress(
        &candidate.destination.eni_id,
        &candidate.destination.security_group_rules,
        &candidate.traffic,
        &source_peer,
    );
    log_layer(
        EvaluationLayer::SgIngress,
        &candidate.destination.eni_id,
        &sg_ingress_verdict,
    );
    steps.push(EvaluationStep {
        layer: EvaluationLayer::SgIngress,
        resource_id: candidate.destination.eni_id.clone(),
        verdict: sg_ingress_verdict,
    });

    finish(candidate, steps)
}

/// Logs one layer's verdict at `debug`. Never logs rule contents — only
/// resource ids and the verdict's discriminant/reason, neither of which
/// can carry customer CIDRs.
fn log_layer(layer: EvaluationLayer, resource_id: &str, verdict: &Verdict) {
    debug!(?layer, resource_id, ?verdict, "evaluated layer");
}

fn finish(candidate: &PathCandidate, steps: Vec<EvaluationStep>) -> ReachabilityFinding {
    let reachability = combine_verdicts(&steps);
    finish_with(candidate, PathEvidence { steps }, reachability)
}

fn finish_with(
    candidate: &PathCandidate,
    path_evidence: PathEvidence,
    reachability: Reachability,
) -> ReachabilityFinding {
    let severity = severity_for(&reachability);
    let finding = ReachabilityFinding {
        computed_at: now_rfc3339(),
        source: candidate.source.eni_id.clone(),
        destination_boundary: candidate.destination_boundary.clone(),
        path_evidence,
        reachability,
        severity,
    };
    info!(
        source = %finding.source,
        destination_boundary = %finding.destination_boundary,
        severity = ?finding.severity,
        "reachability finding computed",
    );
    finding
}

/// Folds a [`PathEvidence`]'s steps into one [`Reachability`] outcome.
///
/// `Denied` always wins over `Indeterminate`, even when both are present
/// across different layers: a definite block on one layer makes the path
/// unreachable regardless of what an unresolvable rule on a *different*
/// layer might have said had it resolved. Treating an unresolved-but-moot
/// layer as "maybe reachable" once another layer already denied the
/// traffic would report indeterminate — demanding human review — for a
/// case that is already provably blocked and needs none. `Indeterminate`
/// applies only when no layer produced a definite deny.
fn combine_verdicts(steps: &[EvaluationStep]) -> Reachability {
    let mut indeterminate_layers = Vec::new();
    for step in steps {
        match &step.verdict {
            Verdict::Denied { .. } => return Reachability::NotReachable,
            Verdict::Indeterminate { .. } => indeterminate_layers.push(step.layer),
            Verdict::Allowed { .. } => {}
        }
    }
    if indeterminate_layers.is_empty() {
        Reachability::Reachable
    } else {
        Reachability::Indeterminate {
            layers: indeterminate_layers,
        }
    }
}

/// Maps a [`Reachability`] outcome to [`Severity`]. No regime-aware
/// boundary lookup exists yet (no `RegulatedBoundary` domain type is
/// reachable from [`PathCandidate`] today), so this is deliberately one
/// flat `match`, not a scoring engine. `Reachable` is the worst case for a
/// regulated boundary (`High`); `Indeterminate` demands human review
/// (`Medium`); `NotReachable` carries the least signal this enum can
/// express (`Low` — [`Severity`] has no dedicated "informational" variant).
/// `Severity::Critical` is unused here, reserved for a future
/// regime-aware milestone.
fn severity_for(reachability: &Reachability) -> Severity {
    match reachability {
        Reachability::Reachable => Severity::High,
        Reachability::Indeterminate { .. } => Severity::Medium,
        Reachability::NotReachable => Severity::Low,
    }
}

/// Current UTC time as an RFC 3339 string (`YYYY-MM-DDTHH:MM:SSZ`), with no
/// `chrono`/`time` dependency: pure integer arithmetic over
/// [`std::time::SystemTime`]'s epoch offset (Howard Hinnant's
/// civil-from-days algorithm). Isolated to this one function so
/// `evaluate_candidate`'s reachability/evidence logic stays deterministic
/// and unit-testable without touching the wall clock.
fn now_rfc3339() -> String {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO);
    let total_seconds = elapsed.as_secs();
    let days = (total_seconds / 86_400) as i64;
    let seconds_of_day = total_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days-since-Unix-epoch to (year, month, day), civil calendar, UTC.
/// Howard Hinnant's `civil_from_days`:
/// <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pretty_assertions::assert_eq;

    use super::*;
    use crate::domain::rule::{Action, Direction, NaclRule, PortRange, RuleTarget, SgRule};
    use crate::evaluate::path::EndpointCandidate;
    use crate::evaluate::{DenyReason, IndeterminateReason, Protocol, RuleRef, Traffic};

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
            port_range: PortRange::new(443, 443).ok(),
            target: RuleTarget::Cidr {
                cidr: "0.0.0.0/0".to_string(),
            },
            resolved: true,
        }
    }

    fn deny_all_sg_ref_rule(direction: Direction, security_group_id: &str) -> SgRule {
        SgRule {
            direction,
            protocol: "tcp".to_string(),
            port_range: PortRange::new(443, 443).ok(),
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
            port_range: PortRange::new(443, 443).ok(),
            cidr: "0.0.0.0/0".to_string(),
            action: Action::Allow,
        }
    }

    fn deny_all_nacl_rule(rule_number: u16, direction: Direction) -> NaclRule {
        NaclRule {
            rule_number,
            direction,
            protocol: "tcp".to_string(),
            port_range: PortRange::new(443, 443).ok(),
            cidr: "0.0.0.0/0".to_string(),
            action: Action::Deny,
        }
    }

    fn allowing_endpoint(eni_id: &str, subnet_id: &str) -> EndpointCandidate {
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

    fn allowing_candidate() -> PathCandidate {
        PathCandidate {
            source: allowing_endpoint("eni-source", "subnet-source"),
            destination: allowing_endpoint("eni-destination", "subnet-destination"),
            route_exists: true,
            traffic: sample_traffic(),
            destination_boundary: "boundary-pci-prod".to_string(),
        }
    }

    fn step(layer: EvaluationLayer, verdict: Verdict) -> EvaluationStep {
        EvaluationStep {
            layer,
            resource_id: "resource-0example".to_string(),
            verdict,
        }
    }

    fn allowed_step(layer: EvaluationLayer) -> EvaluationStep {
        step(
            layer,
            Verdict::Allowed {
                matched_by: RuleRef::NetworkAcl {
                    network_acl_id: "acl-0example".to_string(),
                    rule_number: 100,
                },
            },
        )
    }

    fn denied_step(layer: EvaluationLayer) -> EvaluationStep {
        step(
            layer,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            },
        )
    }

    fn indeterminate_step(layer: EvaluationLayer) -> EvaluationStep {
        step(
            layer,
            Verdict::Indeterminate {
                reason: IndeterminateReason::UnresolvedReference {
                    security_group_id: "sg-cross-account".to_string(),
                },
            },
        )
    }

    #[test]
    fn combine_verdicts_all_allowed_returns_reachable() {
        // Arrange
        let steps = vec![
            allowed_step(EvaluationLayer::SgEgress),
            allowed_step(EvaluationLayer::NaclEgress),
            allowed_step(EvaluationLayer::NaclIngress),
            allowed_step(EvaluationLayer::SgIngress),
        ];

        // Act
        let reachability = combine_verdicts(&steps);

        // Assert
        assert_eq!(reachability, Reachability::Reachable);
    }

    #[test]
    fn combine_verdicts_single_deny_returns_not_reachable() {
        // Arrange
        let steps = vec![
            allowed_step(EvaluationLayer::SgEgress),
            denied_step(EvaluationLayer::NaclEgress),
        ];

        // Act
        let reachability = combine_verdicts(&steps);

        // Assert
        assert_eq!(reachability, Reachability::NotReachable);
    }

    #[test]
    fn combine_verdicts_indeterminate_without_deny_returns_indeterminate() {
        // Arrange
        let steps = vec![
            indeterminate_step(EvaluationLayer::SgEgress),
            allowed_step(EvaluationLayer::NaclEgress),
        ];

        // Act
        let reachability = combine_verdicts(&steps);

        // Assert
        assert_eq!(
            reachability,
            Reachability::Indeterminate {
                layers: vec![EvaluationLayer::SgEgress]
            }
        );
    }

    #[test]
    fn combine_verdicts_deny_and_indeterminate_returns_not_reachable() {
        // Arrange: precedence pinned — Denied beats Indeterminate even
        // when the indeterminate layer was consulted first.
        let steps = vec![
            indeterminate_step(EvaluationLayer::SgEgress),
            denied_step(EvaluationLayer::NaclEgress),
        ];

        // Act
        let reachability = combine_verdicts(&steps);

        // Assert
        assert_eq!(reachability, Reachability::NotReachable);
    }

    #[test]
    fn combine_verdicts_indeterminate_records_which_layer_was_unresolved() {
        // Arrange
        let steps = vec![
            allowed_step(EvaluationLayer::SgEgress),
            indeterminate_step(EvaluationLayer::NaclEgress),
            indeterminate_step(EvaluationLayer::NaclIngress),
        ];

        // Act
        let reachability = combine_verdicts(&steps);

        // Assert
        assert_eq!(
            reachability,
            Reachability::Indeterminate {
                layers: vec![EvaluationLayer::NaclEgress, EvaluationLayer::NaclIngress],
            }
        );
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_route_not_exists_short_circuits() {
        // Arrange
        let mut candidate = allowing_candidate();
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
    async fn rule_intersection_evaluator_all_layers_allow_returns_reachable_finding() {
        // Arrange
        let candidate = allowing_candidate();
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        assert_eq!(finding.reachability, Reachability::Reachable);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.source, "eni-source");
        assert_eq!(finding.destination_boundary, "boundary-pci-prod");
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
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_sg_egress_deny_short_circuits_evidence() {
        // Arrange
        let mut candidate = allowing_candidate();
        candidate.source.security_group_rules = vec![]; // empty egress -> denied
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        assert_eq!(finding.reachability, Reachability::NotReachable);
        let layers: Vec<EvaluationLayer> = finding
            .path_evidence
            .steps
            .iter()
            .map(|step| step.layer)
            .collect();
        assert_eq!(layers, vec![EvaluationLayer::SgEgress]);
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_nacl_egress_deny_short_circuits_before_nacl_ingress() {
        // Arrange
        let mut candidate = allowing_candidate();
        candidate.source.nacl_rules = vec![deny_all_nacl_rule(100, Direction::Egress)];
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        let layers: Vec<EvaluationLayer> = finding
            .path_evidence
            .steps
            .iter()
            .map(|step| step.layer)
            .collect();
        assert_eq!(
            layers,
            vec![EvaluationLayer::SgEgress, EvaluationLayer::NaclEgress]
        );
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_nacl_ingress_deny_short_circuits_before_sg_ingress() {
        // Arrange
        let mut candidate = allowing_candidate();
        candidate.destination.nacl_rules = vec![deny_all_nacl_rule(100, Direction::Ingress)];
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
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
                EvaluationLayer::NaclIngress
            ]
        );
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_unresolved_sg_ref_returns_indeterminate_not_denied() {
        // Arrange
        let mut candidate = allowing_candidate();
        candidate.source.security_group_rules =
            vec![deny_all_sg_ref_rule(Direction::Egress, "sg-cross-account")];
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        assert_eq!(
            finding.reachability,
            Reachability::Indeterminate {
                layers: vec![EvaluationLayer::SgEgress]
            }
        );
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_sg_egress_uses_destination_peer_identity() {
        // Arrange: source's egress rule references a SG that only the
        // destination is a member of. Swapping source/destination peer
        // identity would deny this traffic instead of allowing it.
        let mut candidate = allowing_candidate();
        candidate.source.security_group_rules = vec![deny_all_sg_ref_rule(
            Direction::Egress,
            "sg-destination-member",
        )];
        candidate.source.security_group_rules[0].resolved = true;
        candidate.destination.peer_security_group_ids = vec!["sg-destination-member".to_string()];
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        let sg_egress_step = &finding.path_evidence.steps[0];
        assert!(matches!(sg_egress_step.verdict, Verdict::Allowed { .. }));
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_sg_ingress_uses_source_peer_identity() {
        // Arrange: destination's ingress rule references a SG that only
        // the source is a member of.
        let mut candidate = allowing_candidate();
        candidate.destination.security_group_rules =
            vec![deny_all_sg_ref_rule(Direction::Ingress, "sg-source-member")];
        candidate.destination.security_group_rules[0].resolved = true;
        candidate.source.peer_security_group_ids = vec!["sg-source-member".to_string()];
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        let sg_ingress_step = finding.path_evidence.steps.last().unwrap_or_else(|| {
            panic!("all four layers allow, so evidence must contain the sg ingress step")
        });
        assert_eq!(sg_ingress_step.layer, EvaluationLayer::SgIngress);
        assert!(matches!(sg_ingress_step.verdict, Verdict::Allowed { .. }));
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_nacl_egress_uses_source_subnet_not_destination() {
        // Arrange: only the source subnet's NACL denies egress; the
        // destination subnet's NACL (if consulted for egress by mistake)
        // would allow.
        let mut candidate = allowing_candidate();
        candidate.source.nacl_rules = vec![deny_all_nacl_rule(100, Direction::Egress)];
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        let nacl_egress_step = &finding.path_evidence.steps[1];
        assert_eq!(nacl_egress_step.resource_id, "subnet-source");
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_nacl_ingress_uses_destination_subnet_not_source() {
        // Arrange
        let candidate = allowing_candidate();
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        let nacl_ingress_step = &finding.path_evidence.steps[2];
        assert_eq!(nacl_ingress_step.resource_id, "subnet-destination");
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_evidence_step_order_is_sg_egress_nacl_egress_nacl_ingress_sg_ingress(
    ) {
        // Arrange
        let candidate = allowing_candidate();
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let finding = evaluator
            .evaluate(&candidate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
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
    }

    #[tokio::test]
    async fn rule_intersection_evaluator_severity_matches_reachability_outcome() {
        // Arrange
        let reachable = allowing_candidate();
        let mut not_reachable = allowing_candidate();
        not_reachable.source.security_group_rules = vec![];
        let mut indeterminate = allowing_candidate();
        indeterminate.source.security_group_rules =
            vec![deny_all_sg_ref_rule(Direction::Egress, "sg-cross-account")];
        let evaluator = RuleIntersectionEvaluator;

        // Act
        let reachable_finding = evaluator
            .evaluate(&reachable)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));
        let not_reachable_finding = evaluator
            .evaluate(&not_reachable)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));
        let indeterminate_finding = evaluator
            .evaluate(&indeterminate)
            .await
            .unwrap_or_else(|error| panic!("structurally valid candidate must not error: {error}"));

        // Assert
        assert_eq!(reachable_finding.severity, Severity::High);
        assert_eq!(not_reachable_finding.severity, Severity::Low);
        assert_eq!(indeterminate_finding.severity, Severity::Medium);
    }
}
