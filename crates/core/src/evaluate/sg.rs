//! Security group rule evaluator (M2-T2).
//!
//! Security groups are stateful and allow-only: there is no explicit-deny
//! rule type (unlike NACLs), and a security group's rules for a given
//! direction are evaluated as an **unordered union** — if *any* rule
//! matches, the traffic is allowed, regardless of rule order. A rule whose
//! protocol is the AWS "all protocols" sentinel (`-1`) matches every
//! protocol and **ignores port range entirely**, even if the rule happens
//! to carry one. See
//! <https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html>.
//!
//! A malformed `RuleTarget::Cidr` string or an unrecognized `SgRule::protocol`
//! string is treated as an inert non-match, never a panic or a propagated
//! error: values reaching this module are expected to already be validated
//! at the ingestion boundary (`crate::ingest::map`, which returns
//! `MappingError` for structurally invalid fields) or hand-built in tests,
//! and the functions here are mandated to be pure (`-> Verdict`, not
//! `-> Result<Verdict, _>`).

use crate::domain::rule::{Direction, RuleTarget, SgRule};
use crate::evaluate::{
    cidr_contains, port_matches, rule_protocol_matches, DenyReason, IndeterminateReason, RuleRef,
    Traffic, Verdict,
};

/// The set of security groups the peer ENI belongs to, for matching
/// [`RuleTarget::SecurityGroupRef`] rules. The peer's IP address is not
/// duplicated here — read it from [`Traffic::peer_address`].
#[derive(Debug, Clone, Copy)]
pub struct PeerIdentity<'a> {
    /// Security group ids the peer ENI is a member of. A plain slice, not a
    /// `HashSet`: AWS caps ENI security-group membership at a small number
    /// (5 by default), so a linear `.contains()`-style scan is cheaper than
    /// hashing and needs no extra import.
    pub security_group_ids: &'a [String],
}

/// Evaluates `rules` — one security group's rules, filtered to the matching
/// direction — against one concrete `Traffic` flow and its peer's identity.
///
/// # AWS semantics encoded here
///
/// Security groups are stateful and allow-only: there is no explicit-deny
/// rule type (unlike NACLs), and a security group's rules for a given
/// direction are evaluated as an **unordered union** — if *any* rule
/// matches, the traffic is allowed, regardless of rule order. A rule whose
/// protocol is the AWS "all protocols" sentinel (`-1`) matches every
/// protocol and **ignores port range entirely**. See
/// <https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html>.
///
/// Returns [`Verdict::Denied`] with [`DenyReason::NoMatchingRule`] both when
/// no rule in `rules` has this direction and when `rules` is empty outright
/// — security groups have an implicit deny-all, there is no separate
/// "no rules configured" state.
///
/// [`Verdict::Indeterminate`] outranks `Denied` but never an `Allowed`: a
/// resolved allow anywhere in the rule set wins even if an
/// earlier-considered rule referenced an unresolved cross-account security
/// group. See [`Outcome`]'s fold order for why this holds regardless of
/// `rules`' iteration order.
pub fn evaluate_sg_egress(
    security_group_id: &str,
    rules: &[SgRule],
    traffic: &Traffic,
    peer: &PeerIdentity,
) -> Verdict {
    evaluate(security_group_id, rules, Direction::Egress, traffic, peer)
}

/// See [`evaluate_sg_egress`] — identical semantics, filtered to
/// `Direction::Ingress` rules instead.
pub fn evaluate_sg_ingress(
    security_group_id: &str,
    rules: &[SgRule],
    traffic: &Traffic,
    peer: &PeerIdentity,
) -> Verdict {
    evaluate(security_group_id, rules, Direction::Ingress, traffic, peer)
}

fn evaluate(
    security_group_id: &str,
    rules: &[SgRule],
    direction: Direction,
    traffic: &Traffic,
    peer: &PeerIdentity,
) -> Verdict {
    let outcome = rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.direction == direction)
        .map(|(index, rule)| classify_rule(rule, index, security_group_id, traffic, peer))
        .fold(Outcome::Denied, combine);

    match outcome {
        Outcome::Allowed { matched_by } => Verdict::Allowed { matched_by },
        Outcome::Indeterminate { security_group_id } => Verdict::Indeterminate {
            reason: IndeterminateReason::UnresolvedReference { security_group_id },
        },
        Outcome::Denied => Verdict::Denied {
            reason: DenyReason::NoMatchingRule,
        },
    }
}

/// Accumulates the union-of-rules result across a rule set, folding to the
/// strongest available verdict regardless of visitation order — `Allowed`
/// beats `Indeterminate` beats `Denied`, so which rule is visited first
/// never changes the final [`Verdict`] discriminant (only which `rule_index`
/// is cited in an `Allowed`, when more than one rule would allow).
enum Outcome {
    Allowed { matched_by: RuleRef },
    Indeterminate { security_group_id: String },
    Denied,
}

fn combine(acc: Outcome, next: Outcome) -> Outcome {
    match (acc, next) {
        (Outcome::Allowed { matched_by }, _) | (_, Outcome::Allowed { matched_by }) => {
            Outcome::Allowed { matched_by }
        }
        (Outcome::Indeterminate { security_group_id }, _)
        | (_, Outcome::Indeterminate { security_group_id }) => {
            Outcome::Indeterminate { security_group_id }
        }
        (Outcome::Denied, Outcome::Denied) => Outcome::Denied,
    }
}

/// Classifies a single rule against `traffic`/`peer`, independent of any
/// other rule in the set. `security_group_id`/`rule_index` are threaded
/// through only to build `RuleRef::SecurityGroup` on an `Allowed` outcome —
/// classification itself does not need the rule's position.
fn classify_rule(
    rule: &SgRule,
    rule_index: usize,
    security_group_id: &str,
    traffic: &Traffic,
    peer: &PeerIdentity,
) -> Outcome {
    if !rule_protocol_matches(&rule.protocol, traffic.protocol) {
        return Outcome::Denied;
    }
    // "-1"/All skips port matching entirely, regardless of what port_range
    // the rule happens to carry.
    if rule.protocol != "-1" && !port_matches(rule.port_range, traffic.port) {
        return Outcome::Denied;
    }
    match &rule.target {
        RuleTarget::Cidr { cidr } => match cidr_contains(cidr, traffic.peer_address) {
            Some(true) => Outcome::Allowed {
                matched_by: RuleRef::SecurityGroup {
                    security_group_id: security_group_id.to_string(),
                    rule_index,
                },
            },
            // Some(false): parsed but doesn't contain the peer address.
            // None: cidr string failed to parse — inert non-match, see the
            // module doc comment for why this never panics/errors.
            Some(false) | None => Outcome::Denied,
        },
        RuleTarget::SecurityGroupRef {
            security_group_id: ref_id,
        } => {
            if !rule.resolved {
                return Outcome::Indeterminate {
                    security_group_id: ref_id.clone(),
                };
            }
            // Never consult any IP field here — membership only. A peer's
            // IP can coincidentally match some CIDR without the peer ever
            // being a member of the referenced group; the reverse
            // confusion (comparing IPs here) is the bug this branch exists
            // to rule out.
            if peer.security_group_ids.iter().any(|id| id == ref_id) {
                Outcome::Allowed {
                    matched_by: RuleRef::SecurityGroup {
                        security_group_id: security_group_id.to_string(),
                        rule_index,
                    },
                }
            } else {
                Outcome::Denied
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pretty_assertions::assert_eq;

    use crate::domain::rule::PortRange;
    use crate::evaluate::Protocol;

    use super::*;

    fn port_range(from_port: u16, to_port: u16) -> PortRange {
        PortRange::new(from_port, to_port)
            .unwrap_or_else(|error| panic!("expected a valid port range: {error}"))
    }

    fn cidr_rule(
        direction: Direction,
        protocol: &str,
        port_range: Option<PortRange>,
        cidr: &str,
    ) -> SgRule {
        SgRule {
            direction,
            protocol: protocol.to_string(),
            port_range,
            target: RuleTarget::Cidr {
                cidr: cidr.to_string(),
            },
            resolved: true,
        }
    }

    fn sg_ref_rule(
        direction: Direction,
        protocol: &str,
        port_range: Option<PortRange>,
        security_group_id: &str,
        resolved: bool,
    ) -> SgRule {
        SgRule {
            direction,
            protocol: protocol.to_string(),
            port_range,
            target: RuleTarget::SecurityGroupRef {
                security_group_id: security_group_id.to_string(),
            },
            resolved,
        }
    }

    fn tcp_traffic(port: u16, peer_address: IpAddr) -> Traffic {
        Traffic {
            protocol: Protocol::Tcp,
            port: Some(port),
            peer_address,
        }
    }

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    #[test]
    fn evaluate_sg_egress_matching_cidr_rule_returns_allowed() {
        // Arrange
        let rules = [cidr_rule(
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "0.0.0.0/0",
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let verdict = evaluate_sg_egress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Allowed {
                matched_by: RuleRef::SecurityGroup {
                    security_group_id: "sg-0example".to_string(),
                    rule_index: 0,
                },
            }
        );
    }

    #[test]
    fn evaluate_sg_egress_peer_outside_all_cidrs_returns_denied() {
        // Arrange
        let rules = [cidr_rule(
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "10.0.0.0/8",
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let verdict = evaluate_sg_egress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }

    #[test]
    fn evaluate_sg_ingress_peer_member_of_referenced_group_returns_allowed() {
        // Arrange
        let rules = [sg_ref_rule(
            Direction::Ingress,
            "tcp",
            Some(port_range(443, 443)),
            "sg-referenced",
            true,
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let membership = vec!["sg-referenced".to_string()];
        let peer = PeerIdentity {
            security_group_ids: &membership,
        };

        // Act
        let verdict = evaluate_sg_ingress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Allowed {
                matched_by: RuleRef::SecurityGroup {
                    security_group_id: "sg-0example".to_string(),
                    rule_index: 0,
                },
            }
        );
    }

    #[test]
    fn evaluate_sg_ingress_peer_not_member_of_referenced_group_returns_denied() {
        // Arrange
        let rules = [sg_ref_rule(
            Direction::Ingress,
            "tcp",
            Some(port_range(443, 443)),
            "sg-referenced",
            true,
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let membership = vec!["sg-other".to_string()];
        let peer = PeerIdentity {
            security_group_ids: &membership,
        };

        // Act
        let verdict = evaluate_sg_ingress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }

    #[test]
    fn evaluate_sg_ingress_referenced_group_ip_matches_but_membership_does_not_returns_denied() {
        // Arrange
        let rules = [sg_ref_rule(
            Direction::Ingress,
            "tcp",
            Some(port_range(443, 443)),
            "sg-referenced",
            true,
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let membership = vec!["sg-other".to_string()];
        let peer = PeerIdentity {
            security_group_ids: &membership,
        };

        // Act
        let verdict = evaluate_sg_ingress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }

    #[test]
    fn evaluate_sg_egress_protocol_all_ignores_port_range_returns_allowed() {
        // Arrange
        let rules = [cidr_rule(Direction::Egress, "-1", None, "0.0.0.0/0")];
        let traffic = Traffic {
            protocol: Protocol::Udp,
            port: Some(9999),
            peer_address: v4([203, 0, 113, 10]),
        };
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let verdict = evaluate_sg_egress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Allowed {
                matched_by: RuleRef::SecurityGroup {
                    security_group_id: "sg-0example".to_string(),
                    rule_index: 0,
                },
            }
        );
    }

    #[test]
    fn evaluate_sg_egress_protocol_mismatch_returns_denied() {
        // Arrange
        let rules = [cidr_rule(
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "0.0.0.0/0",
        )];
        let traffic = Traffic {
            protocol: Protocol::Udp,
            port: Some(443),
            peer_address: v4([203, 0, 113, 10]),
        };
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let verdict = evaluate_sg_egress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }

    #[test]
    fn evaluate_sg_egress_port_outside_rule_range_returns_denied() {
        // Arrange
        let rules = [cidr_rule(
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "0.0.0.0/0",
        )];
        let traffic = tcp_traffic(8080, v4([203, 0, 113, 10]));
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let verdict = evaluate_sg_egress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }

    #[test]
    fn evaluate_sg_egress_unresolved_reference_returns_indeterminate() {
        // Arrange
        let rules = [sg_ref_rule(
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "sg-cross-account",
            false,
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let verdict = evaluate_sg_egress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Indeterminate {
                reason: IndeterminateReason::UnresolvedReference {
                    security_group_id: "sg-cross-account".to_string(),
                },
            }
        );
    }

    #[test]
    fn evaluate_sg_egress_resolved_allow_alongside_unresolved_rule_returns_allowed() {
        // Arrange
        let rules = [
            sg_ref_rule(
                Direction::Egress,
                "tcp",
                Some(port_range(443, 443)),
                "sg-cross-account",
                false,
            ),
            cidr_rule(
                Direction::Egress,
                "tcp",
                Some(port_range(443, 443)),
                "0.0.0.0/0",
            ),
        ];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let verdict = evaluate_sg_egress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert!(matches!(verdict, Verdict::Allowed { .. }));
    }

    #[test]
    fn evaluate_sg_egress_rule_order_reversed_returns_same_verdict() {
        // Arrange
        let unresolved = sg_ref_rule(
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "sg-cross-account",
            false,
        );
        let resolved_allow = cidr_rule(
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "0.0.0.0/0",
        );
        let forward_order = [unresolved.clone(), resolved_allow.clone()];
        let reversed_order = [resolved_allow, unresolved];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let forward_verdict = evaluate_sg_egress("sg-0example", &forward_order, &traffic, &peer);
        let reversed_verdict = evaluate_sg_egress("sg-0example", &reversed_order, &traffic, &peer);

        // Assert
        assert!(matches!(forward_verdict, Verdict::Allowed { .. }));
        assert!(matches!(reversed_verdict, Verdict::Allowed { .. }));
    }

    #[test]
    fn evaluate_sg_egress_empty_rule_set_returns_denied() {
        // Arrange
        let rules: [SgRule; 0] = [];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));
        let peer = PeerIdentity {
            security_group_ids: &[],
        };

        // Act
        let verdict = evaluate_sg_egress("sg-0example", &rules, &traffic, &peer);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }
}
