//! Property tests for the NACL evaluator's ordering semantics (M2-T4).
//!
//! Integration test: exercises only `aws_net_hound_core`'s public API
//! (`evaluate_nacl_egress`), so it pins observable behavior, not
//! implementation details reachable only from inside the `evaluate` module.

use std::net::{IpAddr, Ipv4Addr};

use aws_net_hound_core::domain::rule::{Action, Direction, NaclRule, PortRange};
use aws_net_hound_core::evaluate::nacl::evaluate_nacl_egress;
use aws_net_hound_core::evaluate::{DenyReason, Protocol, RuleRef, Traffic, Verdict};
use proptest::prelude::*;
use proptest::sample::select;

const NETWORK_ACL_ID: &str = "acl-0example";

// Small, deliberately overlapping domains: collisions between rules are the
// interesting case here, not coverage of the full u16/CIDR space.
const CIDRS: [&str; 3] = ["0.0.0.0/0", "10.0.0.0/8", "10.1.2.0/24"];
const PORTS: [u16; 4] = [22, 80, 443, 8080];

fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![Just(Action::Allow), Just(Action::Deny)]
}

fn cidr_strategy() -> impl Strategy<Value = &'static str> {
    select(&CIDRS[..])
}

fn port_strategy() -> impl Strategy<Value = u16> {
    select(&PORTS[..])
}

/// Generates a single-port `PortRange` (`from_port == to_port`) — ranges
/// wider than one port aren't needed to exercise ordering collisions.
fn port_range_strategy() -> impl Strategy<Value = PortRange> {
    port_strategy().prop_map(|port| {
        PortRange::new(port, port).unwrap_or_else(|error| {
            unreachable!("single-port range {port} is always valid: {error}")
        })
    })
}

fn nacl_rule_strategy() -> impl Strategy<Value = NaclRule> {
    (
        1u16..=32_000,
        port_range_strategy(),
        cidr_strategy(),
        action_strategy(),
    )
        .prop_map(|(rule_number, port_range, cidr, action)| NaclRule {
            rule_number,
            direction: Direction::Egress,
            protocol: "tcp".to_string(),
            port_range: Some(port_range),
            cidr: cidr.to_string(),
            action,
        })
}

fn traffic_strategy() -> impl Strategy<Value = Traffic> {
    (port_strategy(), 0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255).prop_map(
        |(port, o1, o2, o3, o4)| Traffic {
            protocol: Protocol::Tcp,
            port: Some(port),
            peer_address: IpAddr::V4(Ipv4Addr::new(o1, o2, o3, o4)),
        },
    )
}

/// Deterministic shuffle: reverses chunks of the rule set by index parity so
/// the permutation is a pure function of the input, not a second RNG draw —
/// proptest's `Vec` shrinking already explores insertion-order variation
/// on its own, this only needs to produce *some* different order.
fn permute(rules: &[NaclRule]) -> Vec<NaclRule> {
    let mut permuted = rules.to_vec();
    permuted.reverse();
    permuted
}

/// Naive reference oracle, written independently of `evaluate_nacl_egress`:
/// lowest `rule_number` among matching rules wins, `None` is implicit deny.
/// Must not call the production function — the whole point is a second,
/// dumber implementation of "what should the answer be."
fn naive_first_match_verdict(rules: &[NaclRule], traffic: &Traffic) -> Verdict {
    let matched = rules
        .iter()
        .filter(|rule| rule.direction == Direction::Egress)
        .filter(|rule| rule_matches_reference(rule, traffic))
        .min_by_key(|rule| rule.rule_number);

    match matched {
        Some(rule) => {
            let matched_by = RuleRef::NetworkAcl {
                network_acl_id: NETWORK_ACL_ID.to_string(),
                rule_number: rule.rule_number,
            };
            match rule.action {
                Action::Allow => Verdict::Allowed { matched_by },
                Action::Deny => Verdict::Denied {
                    reason: DenyReason::ExplicitDeny { matched_by },
                },
            }
        }
        None => Verdict::Denied {
            reason: DenyReason::NoMatchingRule,
        },
    }
}

/// Independent match predicate — deliberately re-derives CIDR containment
/// and port matching rather than calling the private helpers `nacl.rs`
/// itself uses, since this file cannot reach `pub(super)` items anyway.
fn rule_matches_reference(rule: &NaclRule, traffic: &Traffic) -> bool {
    if traffic.port != rule.port_range.map(|range| range.from_port()) {
        // Every generated rule/traffic pair here is single-port; a rule
        // matches only when its one port equals the traffic's one port.
        return false;
    }

    let IpAddr::V4(peer) = traffic.peer_address else {
        unreachable!("traffic_strategy only generates IPv4 addresses");
    };
    let Some((network_str, prefix_str)) = rule.cidr.split_once('/') else {
        return false;
    };
    let Ok(IpAddr::V4(network)) = network_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.parse::<u32>() else {
        return false;
    };
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    u32::from(network) & mask == u32::from(peer) & mask
}

proptest! {
    #[test]
    fn evaluate_nacl_any_permutation_of_rules_returns_same_verdict(
        rules in prop::collection::vec(nacl_rule_strategy(), 0..8),
        traffic in traffic_strategy(),
    ) {
        let permuted = permute(&rules);

        let original_verdict = evaluate_nacl_egress(NETWORK_ACL_ID, &rules, &traffic);
        let permuted_verdict = evaluate_nacl_egress(NETWORK_ACL_ID, &permuted, &traffic);

        prop_assert_eq!(original_verdict, permuted_verdict);
    }

    #[test]
    fn evaluate_nacl_verdict_always_equals_lowest_numbered_matching_rule_action(
        rules in prop::collection::vec(nacl_rule_strategy(), 0..8),
        traffic in traffic_strategy(),
    ) {
        let actual = evaluate_nacl_egress(NETWORK_ACL_ID, &rules, &traffic);
        let expected = naive_first_match_verdict(&rules, &traffic);

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn evaluate_nacl_duplicate_rule_numbers_resolve_deterministically(
        rule_number in 1u16..=32_000,
        port_range in port_range_strategy(),
        cidr in cidr_strategy(),
        first_action in action_strategy(),
        second_action in action_strategy(),
        traffic in traffic_strategy(),
    ) {
        let first = NaclRule {
            rule_number,
            direction: Direction::Egress,
            protocol: "tcp".to_string(),
            port_range: Some(port_range),
            cidr: cidr.to_string(),
            action: first_action,
        };
        let second = NaclRule {
            rule_number,
            direction: Direction::Egress,
            protocol: "tcp".to_string(),
            port_range: Some(port_range),
            cidr: cidr.to_string(),
            action: second_action,
        };
        let rules = [first, second];

        // Documented tie-break (see `evaluate_nacl_egress`'s doc comment):
        // among equal `rule_number`s, the stable sort preserves input-slice
        // order, so the first rule in `rules` decides the verdict whenever
        // both match.
        let repeated_a = evaluate_nacl_egress(NETWORK_ACL_ID, &rules, &traffic);
        let repeated_b = evaluate_nacl_egress(NETWORK_ACL_ID, &rules, &traffic);
        prop_assert_eq!(&repeated_a, &repeated_b);

        if rule_matches_reference(&rules[0], &traffic) {
            let expected_matched_by = RuleRef::NetworkAcl {
                network_acl_id: NETWORK_ACL_ID.to_string(),
                rule_number,
            };
            let expected = match rules[0].action {
                Action::Allow => Verdict::Allowed { matched_by: expected_matched_by },
                Action::Deny => Verdict::Denied {
                    reason: DenyReason::ExplicitDeny { matched_by: expected_matched_by },
                },
            };
            prop_assert_eq!(repeated_a, expected);
        }
    }
}
