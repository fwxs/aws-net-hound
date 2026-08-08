//! Security group and network ACL rule domain types.
//!
//! Field names on `SgRule` and `NaclRule` must match the `ALLOWS_EGRESS` /
//! `ALLOWS_INGRESS` / `HAS_RULE` edge properties documented in
//! `crates/core/docs/schema.md` — that document is authoritative, these
//! types are derived from it.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned when constructing a rule domain type from invalid input.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuleError {
    /// `from_port` was greater than `to_port`.
    #[error("invalid port range: from_port ({from_port}) is greater than to_port ({to_port})")]
    InvertedPortRange { from_port: u16, to_port: u16 },
}

/// Traffic direction a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Direction {
    Ingress,
    Egress,
}

/// An inclusive port range, `from_port <= to_port`.
///
/// Absent entirely (`None` on the owning rule) when the protocol has no
/// port concept (e.g. `-1` for all protocols).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    from_port: u16,
    to_port: u16,
}

impl PortRange {
    /// Builds a port range, rejecting `from_port > to_port`.
    ///
    /// # Example
    ///
    /// ```
    /// use aws_net_hound_core::domain::rule::PortRange;
    ///
    /// let range = PortRange::new(80, 443).unwrap();
    /// assert_eq!(range.from_port(), 80);
    /// ```
    pub fn new(from_port: u16, to_port: u16) -> Result<Self, RuleError> {
        if from_port > to_port {
            return Err(RuleError::InvertedPortRange { from_port, to_port });
        }
        Ok(Self { from_port, to_port })
    }

    /// Lower bound of the range, inclusive.
    pub fn from_port(&self) -> u16 {
        self.from_port
    }

    /// Upper bound of the range, inclusive.
    pub fn to_port(&self) -> u16 {
        self.to_port
    }
}

/// The target of an `ALLOWS_EGRESS` / `ALLOWS_INGRESS` rule.
///
/// Mutually exclusive by construction: a rule targets either a CIDR block
/// or a security-group reference, never both — see `schema.md`'s
/// "Evaluable rules" section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target_kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleTarget {
    /// A CIDR block target, e.g. `0.0.0.0/0`.
    Cidr { cidr: String },
    /// A reference to another security group's id.
    SecurityGroupRef { security_group_id: String },
}

/// A security group egress or ingress rule.
///
/// Mirrors the `ALLOWS_EGRESS` / `ALLOWS_INGRESS` edge properties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SgRule {
    /// Whether this rule is an egress or ingress rule.
    pub direction: Direction,
    /// IANA protocol name or `-1` for all protocols, e.g. `tcp`, `udp`.
    pub protocol: String,
    /// Port range this rule applies to; `None` when the protocol has no
    /// ports (e.g. `-1`).
    pub port_range: Option<PortRange>,
    /// The rule's target: a CIDR or a security-group reference.
    pub target: RuleTarget,
    /// `false` when `target` is a `SecurityGroupRef` that could not be
    /// dereferenced (e.g. cross-account reference in local-audit mode).
    /// An unresolved rule is indeterminate and must not be dropped — the
    /// evaluator (Milestone 2) is responsible for treating it as such.
    pub resolved: bool,
}

/// Allow or deny action of a `NaclRule`. Never a `bool`: NACL evaluation
/// has exactly these two outcomes and no implicit third state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Action {
    Allow,
    Deny,
}

/// A single network ACL rule.
///
/// Mirrors the `HAS_RULE` self-edge properties. `rule_number` is the sole
/// evaluation-order key: NACL semantics are first-match by ascending
/// `rule_number`, never by insertion order, `Vec` position, or any other
/// implicit ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NaclRule {
    /// Ordered integer evaluation-order key. Callers sorting a set of
    /// `NaclRule`s for evaluation must sort explicitly on this field.
    pub rule_number: u16,
    /// Whether this rule applies to ingress or egress traffic.
    pub direction: Direction,
    /// IANA protocol name or `-1` for all protocols.
    pub protocol: String,
    /// Port range this rule applies to; `None` when the protocol has no
    /// ports.
    pub port_range: Option<PortRange>,
    /// CIDR this rule matches against. NACL rules are always CIDR-based —
    /// there is no security-group-reference form, unlike `SgRule`.
    pub cidr: String,
    /// Whether traffic matching this rule is allowed or denied.
    pub action: Action,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn port_range_new_with_inverted_bounds_returns_validation_error() {
        // Arrange
        let from_port = 443;
        let to_port = 80;

        // Act
        let result = PortRange::new(from_port, to_port);

        // Assert
        assert!(matches!(
            result,
            Err(RuleError::InvertedPortRange {
                from_port: 443,
                to_port: 80
            })
        ));
    }

    #[test]
    fn nacl_rules_sort_by_rule_number_ascending() {
        // Arrange
        let mut rules = [
            NaclRule {
                rule_number: 300,
                direction: Direction::Ingress,
                protocol: "tcp".to_string(),
                port_range: PortRange::new(80, 80).ok(),
                cidr: "0.0.0.0/0".to_string(),
                action: Action::Allow,
            },
            NaclRule {
                rule_number: 100,
                direction: Direction::Ingress,
                protocol: "tcp".to_string(),
                port_range: PortRange::new(22, 22).ok(),
                cidr: "10.0.0.0/8".to_string(),
                action: Action::Deny,
            },
            NaclRule {
                rule_number: 200,
                direction: Direction::Egress,
                protocol: "-1".to_string(),
                port_range: None,
                cidr: "0.0.0.0/0".to_string(),
                action: Action::Allow,
            },
        ];

        // Act
        rules.sort_by_key(|rule| rule.rule_number);

        // Assert
        let rule_numbers: Vec<u16> = rules.iter().map(|rule| rule.rule_number).collect();
        assert_eq!(rule_numbers, vec![100, 200, 300]);
    }

    #[test]
    fn sg_rule_serializes_unresolved_reference_with_resolved_false() {
        // Arrange
        let rule = SgRule {
            direction: Direction::Egress,
            protocol: "tcp".to_string(),
            port_range: PortRange::new(443, 443).ok(),
            target: RuleTarget::SecurityGroupRef {
                security_group_id: "sg-0example".to_string(),
            },
            resolved: false,
        };

        // Act
        let json = serde_json_test_roundtrip(&rule);

        // Assert
        assert_eq!(json.resolved, false);
    }

    fn serde_json_test_roundtrip(rule: &SgRule) -> SgRule {
        let serialized = serde_norway::to_string(rule)
            .unwrap_or_else(|error| panic!("failed to serialize SgRule: {error}"));
        serde_norway::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize SgRule: {error}"))
    }
}
