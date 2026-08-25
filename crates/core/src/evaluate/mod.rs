//! Shared types the SG and NACL evaluators (M2-T2, M2-T3) both consume and
//! return. No evaluation logic here — see those tasks.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::domain::rule::PortRange;
use crate::error::EvaluationError;

pub mod candidates;
pub mod engine;
pub mod nacl;
pub mod path;
pub mod sg;

pub use candidates::{assemble_candidates, BoundarySelectors};
pub use engine::RuleIntersectionEvaluator;
pub use path::{EndpointCandidate, EvaluationLayer, EvaluationStep, PathCandidate, PathEvidence};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Whether a rule's raw AWS protocol string matches concrete traffic.
///
/// `rule_protocol` is the rule's raw `protocol` field — AWS's
/// `IpPermission.IpProtocol`/NACL rule protocol verbatim (`"tcp"`, `"udp"`,
/// `"icmp"`, `"icmpv6"`, or `"-1"` for all protocols). Not a full parse into
/// [`Protocol`]: a rule's protocol string alone never carries the
/// `icmp_type`/`code` payload `Protocol::Icmp` requires, so this compares
/// string identity against `traffic_protocol`'s discriminant instead of
/// constructing a `Protocol` to compare with `==`. Shared by [`sg`] and
/// [`nacl`] — both rule types use the same raw-string protocol shape.
pub(super) fn rule_protocol_matches(rule_protocol: &str, traffic_protocol: Protocol) -> bool {
    match rule_protocol {
        "-1" => true,
        "tcp" => matches!(traffic_protocol, Protocol::Tcp),
        "udp" => matches!(traffic_protocol, Protocol::Udp),
        "icmp" | "icmpv6" => matches!(traffic_protocol, Protocol::Icmp { .. }),
        _ => false,
    }
}

/// Whether `traffic_port` (if any) falls within `rule_port_range`
/// (inclusive), for protocols where ports apply.
///
/// Callers must skip this entirely when the rule's protocol is the `-1`
/// all-protocols sentinel, regardless of what `port_range` it carries.
///
/// `rule_port_range: None` (a tcp/udp rule with no port restriction) is
/// treated as "matches every port" — real AWS API usage always sets
/// `from_port`/`to_port` for tcp/udp, but the type does not enforce that,
/// and refusing to match here would silently and incorrectly deny traffic
/// for a validly-constructed rule the type system permits. `traffic_port:
/// None` against `Some(rule_port_range)` is treated as a mismatch — a `None`
/// traffic port carries no port to check inclusion for, so an explicit range
/// cannot be satisfied. Shared by [`sg`] and [`nacl`].
pub(super) fn port_matches(rule_port_range: Option<PortRange>, traffic_port: Option<u16>) -> bool {
    match (rule_port_range, traffic_port) {
        (None, _) => true,
        (Some(range), Some(port)) => (range.from_port()..=range.to_port()).contains(&port),
        (Some(_), None) => false,
    }
}

/// Whether `cidr` (`"ip/prefix_len"`, IPv4 or IPv6) contains `address`.
///
/// Returns `None` if `cidr` fails to parse as a valid CIDR — callers treat
/// this as an inert non-match rather than a panic or a propagated error:
/// values reaching evaluation are expected to already be validated at the
/// ingestion boundary. Shared by [`sg`] and [`nacl`].
pub(super) fn cidr_contains(cidr: &str, address: IpAddr) -> Option<bool> {
    let (network_str, prefix_str) = cidr.split_once('/')?;
    let network: IpAddr = network_str.parse().ok()?;
    let prefix_len: u32 = prefix_str.parse().ok()?;

    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            if prefix_len > 32 {
                return None;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            Some(u32::from(network) & mask == u32::from(address) & mask)
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            if prefix_len > 128 {
                return None;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            Some(u128::from(network) & mask == u128::from(address) & mask)
        }
        // Mixed families (v4 CIDR vs. v6 peer or vice versa) can never
        // contain each other.
        _ => Some(false),
    }
}

/// Test-only builders shared by [`sg`]'s and [`nacl`]'s test modules, so a
/// change to [`Traffic`]/[`PortRange`] or the panic message on an invalid
/// port range only needs editing once, with the compiler catching every
/// caller that needs updating.
#[cfg(test)]
pub(super) mod test_support {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{PortRange, Protocol, Traffic};

    pub(crate) fn port_range(from_port: u16, to_port: u16) -> PortRange {
        PortRange::new(from_port, to_port)
            .unwrap_or_else(|error| panic!("expected a valid port range: {error}"))
    }

    pub(crate) fn tcp_traffic(port: u16, peer_address: IpAddr) -> Traffic {
        Traffic {
            protocol: Protocol::Tcp,
            port: Some(port),
            peer_address,
        }
    }

    pub(crate) fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }
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

    #[test]
    fn rule_protocol_matches_all_sentinel_matches_any_traffic_protocol() {
        // Arrange
        let rule_protocol = "-1";

        // Act
        let matches = rule_protocol_matches(rule_protocol, Protocol::Udp);

        // Assert
        assert!(matches);
    }

    #[test]
    fn rule_protocol_matches_tcp_string_does_not_match_udp_traffic() {
        // Arrange
        let rule_protocol = "tcp";

        // Act
        let matches = rule_protocol_matches(rule_protocol, Protocol::Udp);

        // Assert
        assert!(!matches);
    }

    #[test]
    fn port_matches_none_range_matches_any_port() {
        // Arrange
        let rule_port_range = None;
        let traffic_port = Some(8080);

        // Act
        let matches = port_matches(rule_port_range, traffic_port);

        // Assert
        assert!(matches);
    }

    #[test]
    fn port_matches_some_range_none_traffic_port_returns_false() {
        // Arrange
        let rule_port_range = PortRange::new(443, 443).ok();
        let traffic_port = None;

        // Act
        let matches = port_matches(rule_port_range, traffic_port);

        // Assert
        assert!(!matches);
    }

    #[test]
    fn cidr_contains_address_inside_prefix_returns_some_true() {
        // Arrange
        let cidr = "10.0.0.0/8";
        let address = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

        // Act
        let contains = cidr_contains(cidr, address);

        // Assert
        assert_eq!(contains, Some(true));
    }

    #[test]
    fn cidr_contains_malformed_cidr_returns_none() {
        // Arrange
        let cidr = "not-a-cidr";
        let address = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

        // Act
        let contains = cidr_contains(cidr, address);

        // Assert
        assert_eq!(contains, None);
    }
}
