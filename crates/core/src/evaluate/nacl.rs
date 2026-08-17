//! Network ACL rule evaluator (M2-T3).
//!
//! Network ACLs are stateless and carry both allow and deny rules. A NACL's
//! rules for a given direction are evaluated in **ascending `rule_number`
//! order**, and the **first rule that matches wins**, whether it allows or
//! denies — every later rule is irrelevant for that packet, regardless of
//! what it says. If no explicit rule matches, AWS applies the implicit `*`
//! entry, which is **deny**. See
//! <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html>.
//!
//! `rule_number` is the sole evaluation-order key. `DescribeNetworkAcls`
//! returns entries in no guaranteed order, and ingestion persists them in
//! whatever order the graph query returned them, so this module never
//! assumes the input slice arrives sorted and never mutates the caller's
//! slice to sort it in place — it sorts a local copy of references instead.
//!
//! A malformed `NaclRule::cidr` string or an unrecognized `NaclRule::protocol`
//! string is treated as an inert non-match, never a panic or a propagated
//! error, for the same reason `sg.rs` treats them that way: values reaching
//! this module are expected to already be validated at the ingestion
//! boundary or hand-built in tests, and the functions here are pure
//! (`-> Verdict`, not `-> Result<Verdict, _>`).
//!
//! The implicit `*` deny is produced by falling through every explicit rule,
//! never modeled as a synthetic [`NaclRule`] with `rule_number: u16::MAX` —
//! a synthetic rule would appear in evidence as if it were a real configured
//! rule, and `*` is not a number.

use crate::domain::rule::{Action, Direction, NaclRule};
use crate::evaluate::{
    cidr_contains, port_matches, rule_protocol_matches, DenyReason, RuleRef, Traffic, Verdict,
};

/// Evaluates `rules` — one network ACL's rules, filtered to the matching
/// direction — against one concrete `Traffic` flow.
///
/// # AWS semantics encoded here
///
/// Network ACLs are stateless and evaluated in **ascending `rule_number`
/// order**; the **first matching rule wins**, whether it allows or denies,
/// and every later rule is ignored for that packet. If no rule matches, the
/// implicit `*` entry applies, which is **deny**. See
/// <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html>.
///
/// Returns [`Verdict::Denied`] with [`DenyReason::NoMatchingRule`] both when
/// no rule in `rules` has this direction and when `rules` is empty outright
/// — there is no separate "no rules configured" state, only the implicit
/// deny-all falling through.
pub fn evaluate_nacl_egress(
    network_acl_id: &str,
    rules: &[NaclRule],
    traffic: &Traffic,
) -> Verdict {
    evaluate(network_acl_id, rules, Direction::Egress, traffic)
}

/// See [`evaluate_nacl_egress`] — identical semantics, filtered to
/// `Direction::Ingress` rules instead.
pub fn evaluate_nacl_ingress(
    network_acl_id: &str,
    rules: &[NaclRule],
    traffic: &Traffic,
) -> Verdict {
    evaluate(network_acl_id, rules, Direction::Ingress, traffic)
}

fn evaluate(
    network_acl_id: &str,
    rules: &[NaclRule],
    direction: Direction,
    traffic: &Traffic,
) -> Verdict {
    let mut candidates: Vec<&NaclRule> = rules
        .iter()
        .filter(|rule| rule.direction == direction)
        .collect();
    // The single most important line in this module: NACL evaluation order
    // is `rule_number` ascending, never insertion order or `Vec` position.
    // `DescribeNetworkAcls` returns rules in no guaranteed order, so this
    // sort is not optional and must never be skipped or assumed already
    // done by the caller.
    candidates.sort_by_key(|rule| rule.rule_number);

    match candidates
        .into_iter()
        .find(|rule| rule_matches(rule, traffic))
    {
        Some(rule) => {
            let matched_by = RuleRef::NetworkAcl {
                network_acl_id: network_acl_id.to_string(),
                rule_number: rule.rule_number,
            };
            match rule.action {
                Action::Allow => Verdict::Allowed { matched_by },
                Action::Deny => Verdict::Denied {
                    reason: DenyReason::ExplicitDeny { matched_by },
                },
            }
        }
        // Fell through every explicit rule: AWS's implicit `*` deny-all.
        None => Verdict::Denied {
            reason: DenyReason::NoMatchingRule,
        },
    }
}

/// Whether a single rule matches `traffic`, independent of any other rule in
/// the set and independent of its `action` — the caller decides what an
/// allow vs. deny match means for the resulting [`Verdict`].
fn rule_matches(rule: &NaclRule, traffic: &Traffic) -> bool {
    if !rule_protocol_matches(&rule.protocol, traffic.protocol) {
        return false;
    }
    // "-1"/All skips port matching entirely, regardless of what port_range
    // the rule happens to carry.
    if rule.protocol != "-1" && !port_matches(rule.port_range, traffic.port) {
        return false;
    }
    matches!(cidr_contains(&rule.cidr, traffic.peer_address), Some(true))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::domain::rule::PortRange;
    use crate::evaluate::test_support::{port_range, tcp_traffic, v4};
    use crate::evaluate::Protocol;

    use super::*;

    fn nacl_rule(
        rule_number: u16,
        direction: Direction,
        protocol: &str,
        port_range: Option<PortRange>,
        cidr: &str,
        action: Action,
    ) -> NaclRule {
        NaclRule {
            rule_number,
            direction,
            protocol: protocol.to_string(),
            port_range,
            cidr: cidr.to_string(),
            action,
        }
    }

    #[test]
    fn evaluate_nacl_lower_numbered_allow_before_higher_numbered_deny_returns_allowed() {
        // Arrange
        let rules = [
            nacl_rule(
                100,
                Direction::Egress,
                "tcp",
                Some(port_range(443, 443)),
                "0.0.0.0/0",
                Action::Allow,
            ),
            nacl_rule(
                200,
                Direction::Egress,
                "tcp",
                Some(port_range(443, 443)),
                "0.0.0.0/0",
                Action::Deny,
            ),
        ];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));

        // Act
        let verdict = evaluate_nacl_egress("nacl-0example", &rules, &traffic);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Allowed {
                matched_by: RuleRef::NetworkAcl {
                    network_acl_id: "nacl-0example".to_string(),
                    rule_number: 100,
                },
            }
        );
    }

    #[test]
    fn evaluate_nacl_lower_numbered_deny_before_higher_numbered_allow_returns_denied() {
        // Arrange
        let rules = [
            nacl_rule(
                100,
                Direction::Egress,
                "tcp",
                Some(port_range(443, 443)),
                "0.0.0.0/0",
                Action::Deny,
            ),
            nacl_rule(
                200,
                Direction::Egress,
                "tcp",
                Some(port_range(443, 443)),
                "0.0.0.0/0",
                Action::Allow,
            ),
        ];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));

        // Act
        let verdict = evaluate_nacl_egress("nacl-0example", &rules, &traffic);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::ExplicitDeny {
                    matched_by: RuleRef::NetworkAcl {
                        network_acl_id: "nacl-0example".to_string(),
                        rule_number: 100,
                    },
                },
            }
        );
    }

    #[test]
    fn evaluate_nacl_rules_supplied_in_reverse_number_order_returns_same_verdict() {
        // Arrange
        let allow = nacl_rule(
            100,
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "0.0.0.0/0",
            Action::Allow,
        );
        let deny = nacl_rule(
            200,
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "0.0.0.0/0",
            Action::Deny,
        );
        let forward_order = [allow.clone(), deny.clone()];
        let reversed_order = [deny, allow];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));

        // Act
        let forward_verdict = evaluate_nacl_egress("nacl-0example", &forward_order, &traffic);
        let reversed_verdict = evaluate_nacl_egress("nacl-0example", &reversed_order, &traffic);

        // Assert
        assert_eq!(forward_verdict, reversed_verdict);
        assert!(matches!(forward_verdict, Verdict::Allowed { .. }));
    }

    #[test]
    fn evaluate_nacl_no_matching_rule_returns_implicit_deny() {
        // Arrange
        let rules = [nacl_rule(
            100,
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "10.0.0.0/8",
            Action::Allow,
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));

        // Act
        let verdict = evaluate_nacl_egress("nacl-0example", &rules, &traffic);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }

    #[test]
    fn evaluate_nacl_empty_rule_set_returns_implicit_deny() {
        // Arrange
        let rules: [NaclRule; 0] = [];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));

        // Act
        let verdict = evaluate_nacl_egress("nacl-0example", &rules, &traffic);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }

    #[test]
    fn evaluate_nacl_egress_rules_do_not_decide_ingress_verdict() {
        // Arrange
        let rules = [nacl_rule(
            100,
            Direction::Egress,
            "tcp",
            Some(port_range(443, 443)),
            "0.0.0.0/0",
            Action::Allow,
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));

        // Act
        let verdict = evaluate_nacl_ingress("nacl-0example", &rules, &traffic);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }

    #[test]
    fn evaluate_nacl_protocol_all_rule_matches_any_port_returns_allowed() {
        // Arrange
        let rules = [nacl_rule(
            100,
            Direction::Egress,
            "-1",
            None,
            "0.0.0.0/0",
            Action::Allow,
        )];
        let traffic = Traffic {
            protocol: Protocol::Udp,
            port: Some(9999),
            peer_address: v4([203, 0, 113, 10]),
        };

        // Act
        let verdict = evaluate_nacl_egress("nacl-0example", &rules, &traffic);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Allowed {
                matched_by: RuleRef::NetworkAcl {
                    network_acl_id: "nacl-0example".to_string(),
                    rule_number: 100,
                },
            }
        );
    }

    #[test]
    fn evaluate_nacl_matched_allow_reports_matching_rule_number() {
        // Arrange
        let rules = [
            nacl_rule(
                50,
                Direction::Ingress,
                "tcp",
                Some(port_range(22, 22)),
                "10.0.0.0/8",
                Action::Deny,
            ),
            nacl_rule(
                150,
                Direction::Ingress,
                "tcp",
                Some(port_range(443, 443)),
                "0.0.0.0/0",
                Action::Allow,
            ),
        ];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));

        // Act
        let verdict = evaluate_nacl_ingress("nacl-0example", &rules, &traffic);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Allowed {
                matched_by: RuleRef::NetworkAcl {
                    network_acl_id: "nacl-0example".to_string(),
                    rule_number: 150,
                },
            }
        );
    }

    #[test]
    fn evaluate_nacl_explicit_deny_reports_deny_reason_not_implicit() {
        // Arrange
        let rules = [nacl_rule(
            100,
            Direction::Ingress,
            "tcp",
            Some(port_range(443, 443)),
            "0.0.0.0/0",
            Action::Deny,
        )];
        let traffic = tcp_traffic(443, v4([203, 0, 113, 10]));

        // Act
        let verdict = evaluate_nacl_ingress("nacl-0example", &rules, &traffic);

        // Assert
        assert_eq!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::ExplicitDeny {
                    matched_by: RuleRef::NetworkAcl {
                        network_acl_id: "nacl-0example".to_string(),
                        rule_number: 100,
                    },
                },
            }
        );
        assert_ne!(
            verdict,
            Verdict::Denied {
                reason: DenyReason::NoMatchingRule,
            }
        );
    }
}
