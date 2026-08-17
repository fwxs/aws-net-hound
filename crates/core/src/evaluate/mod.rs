//! Shared types the SG and NACL evaluators (M2-T2, M2-T3) both consume and
//! return. No evaluation logic here — see those tasks.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::EvaluationError;

pub mod sg;

/// Protocol a [`Traffic`] value carries.
///
/// The AWS wire sentinel `-1` ("all protocols") is mapped to [`Protocol::All`]
/// exactly once, in [`TryFrom<i32>`]'s implementation below — nowhere else in
/// the codebase should test for `-1` directly.
///
/// `Icmp` carries its own `icmp_type`/`code` rather than reusing `Traffic`'s
/// `port`: AWS overloads `from_port`/`to_port` as type/code for ICMP (see
/// `build_port_range` in `crate::ingest::map`), and a single `u16` cannot
/// hold both without ambiguity between "type" and "code". Keeping them on
/// the `Icmp` variant itself means a `Traffic` can never be constructed with
/// a `port` that means nothing for its protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    Udp,
    /// AWS overloads `from_port`/`to_port` as `icmp_type`/`code`; unlike
    /// `TryFrom<i32>` (protocol number only), constructing this variant
    /// requires that pair from the same source `crate::ingest::map` reads.
    Icmp {
        icmp_type: u8,
        code: u8,
    },
    /// AWS `-1`: matches every protocol.
    All,
}

/// The AWS IP protocol number for a [`Protocol`] that carries no per-protocol
/// payload of its own (`Tcp`, `Udp`, `All`), per
/// <https://www.iana.org/assignments/protocol-numbers/>. `-1` is AWS's own
/// sentinel for "all protocols", not an IANA number. `Icmp` is excluded:
/// it also needs `icmp_type`/`code`, which no bare protocol number carries,
/// so it cannot be produced by this conversion — construct it directly.
impl TryFrom<i32> for Protocol {
    type Error = EvaluationError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -1 => Ok(Protocol::All),
            6 => Ok(Protocol::Tcp),
            17 => Ok(Protocol::Udp),
            other => Err(EvaluationError::UnsupportedProtocol { value: other }),
        }
    }
}

/// One concrete traffic flow being evaluated against the SG and NACL layers.
///
/// Constructed once by the caller (M2-T6) and passed by reference to every
/// layer function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Traffic {
    /// Protocol of this traffic, carrying any protocol-specific payload
    /// (e.g. ICMP type/code).
    pub protocol: Protocol,
    /// The concrete peer port this traffic uses; `None` when the protocol
    /// has no port concept (`Icmp`, `All`). `Traffic` carries one port, not
    /// a range — ranges exist only on rules ([`crate::domain::PortRange`]).
    pub port: Option<u16>,
    /// The peer address this traffic is to or from.
    pub peer_address: IpAddr,
}

/// Identifies the rule that produced a [`Verdict::Allowed`], so evidence
/// (M2-T5) is a by-product of evaluation rather than a second pass that
/// re-derives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleRef {
    /// A security group rule. `rule_index` is the matched rule's position
    /// within the `Vec<SgRule>` passed to the evaluator for this security
    /// group — `SgRule` carries no stable id of its own (neither
    /// `crate::domain::rule` nor the `ALLOWS_EGRESS`/`ALLOWS_INGRESS` edge
    /// properties in `schema.md` define one), so this is the only identity
    /// available today. Valid only within the evaluation call that produced
    /// it, not a durable cross-run key.
    SecurityGroup {
        security_group_id: String,
        rule_index: usize,
    },
    /// A network ACL rule, identified by its `HAS_RULE.rule_number` — a
    /// stable, ingestion-sourced key, unlike the SG case above.
    NetworkAcl {
        network_acl_id: String,
        rule_number: u16,
    },
}

/// Why a layer denied traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DenyReason {
    /// No rule matched. For an SG this means no allow rule matched
    /// (security groups have no deny rules); for a NACL it means
    /// evaluation fell through every explicit rule to the implicit `*`
    /// deny-all.
    NoMatchingRule,
    /// An explicit deny rule matched. NACL-only — security groups have no
    /// deny rules to match.
    ExplicitDeny { matched_by: RuleRef },
}

/// Why a layer could not reach a definite allow/deny verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum IndeterminateReason {
    /// The rule that would decide this traffic references a security group
    /// that could not be resolved (`resolved: false` on the rule edge —
    /// most commonly a cross-account reference in local-audit mode).
    UnresolvedReference { security_group_id: String },
}

/// The three-state result every evaluation layer (SG, NACL) returns for a
/// given [`Traffic`].
///
/// `Indeterminate` is deliberately not an error: an unresolved cross-account
/// security-group reference is an expected outcome in local-audit mode (see
/// `resolved: bool` in `schema.md`), and collapsing it to `Denied` would
/// report "not reachable" for traffic that may well be reachable — a silent
/// false negative. [`EvaluationError`] is reserved for input the layer
/// cannot interpret at all (e.g. an unmappable [`Protocol`]), never for an
/// unresolved reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Verdict {
    Allowed { matched_by: RuleRef },
    Denied { reason: DenyReason },
    Indeterminate { reason: IndeterminateReason },
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn protocol_try_from_minus_one_returns_all() {
        // Arrange
        let value: i32 = -1;

        // Act
        let result = Protocol::try_from(value);

        // Assert
        assert!(matches!(result, Ok(Protocol::All)));
    }

    #[test]
    fn protocol_try_from_unknown_number_returns_evaluation_error() {
        // Arrange
        let value: i32 = 253;

        // Act
        let result = Protocol::try_from(value);

        // Assert
        assert!(matches!(
            result,
            Err(EvaluationError::UnsupportedProtocol { value: 253 })
        ));
    }

    #[test]
    fn protocol_try_from_icmp_number_returns_evaluation_error() {
        // Arrange
        let value: i32 = 1;

        // Act
        let result = Protocol::try_from(value);

        // Assert
        // ICMP needs `icmp_type`/`code`, which a bare protocol number
        // cannot supply — construct `Protocol::Icmp { .. }` directly
        // instead of going through this conversion.
        assert!(matches!(
            result,
            Err(EvaluationError::UnsupportedProtocol { value: 1 })
        ));
    }

    #[test]
    fn verdict_serializes_indeterminate_with_reason_preserved() {
        // Arrange
        let verdict = Verdict::Indeterminate {
            reason: IndeterminateReason::UnresolvedReference {
                security_group_id: "sg-0example".to_string(),
            },
        };

        // Act
        let serialized = serde_norway::to_string(&verdict)
            .unwrap_or_else(|error| panic!("failed to serialize Verdict: {error}"));
        let roundtripped: Verdict = serde_norway::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize Verdict: {error}"));

        // Assert
        assert_eq!(roundtripped, verdict);
        assert!(matches!(roundtripped, Verdict::Indeterminate { .. }));
    }

    #[test]
    fn traffic_holds_concrete_port_and_peer_address() {
        // Arrange
        let peer_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        // Act
        let traffic = Traffic {
            protocol: Protocol::Tcp,
            port: Some(443),
            peer_address,
        };

        // Assert
        assert_eq!(traffic.port, Some(443));
        assert_eq!(traffic.peer_address, peer_address);
    }

    #[test]
    fn traffic_icmp_carries_type_and_code_not_port() {
        // Arrange
        let peer_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        // Act
        let traffic = Traffic {
            protocol: Protocol::Icmp {
                icmp_type: 8,
                code: 0,
            },
            port: None,
            peer_address,
        };

        // Assert
        assert!(matches!(
            traffic.protocol,
            Protocol::Icmp {
                icmp_type: 8,
                code: 0
            }
        ));
        assert_eq!(traffic.port, None);
    }
}
