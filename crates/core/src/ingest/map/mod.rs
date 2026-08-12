//! Maps `aws_sdk_ec2::types::*` values into `core::domain` rule types.
//!
//! The SDK types and the domain types disagree on purpose: `IpPermission`
//! is a bag of `Option`s that can carry a CIDR and an SG reference at once,
//! while `SgRule::target` is an enum that forces a choice. This module is
//! where that shape mismatch gets resolved.

pub mod nacl;
pub mod sg;
pub mod topology;

use crate::domain::rule::{PortRange, RuleError};
use crate::error::MappingError;

/// Reads a required `Option<String>` field, or returns a [`MappingError`]
/// naming the resource and field that were missing.
pub(crate) fn require_str<'a>(
    resource_id: &str,
    field: &'static str,
    value: &'a Option<String>,
) -> Result<&'a str, MappingError> {
    value.as_deref().ok_or_else(|| MappingError::InvalidField {
        resource_id: resource_id.to_string(),
        field,
        reason: "field is required but absent".to_string(),
    })
}

/// Normalises an SDK protocol/port-range pair into `Option<PortRange>`.
///
/// `protocol == "-1"` (all protocols) never carries ports, so it short
/// circuits to `None` regardless of what `from_port`/`to_port` contain.
///
/// AWS overloads `from_port`/`to_port` for ICMP as `type`/`code`, and `-1`
/// on either one is the "any" sentinel for that half of the pair (e.g.
/// `from_port=8, to_port=-1` is "Echo Request, any code"). When both are
/// `-1` there is no restriction at all, so this normalises to `None`. When
/// only one side is `-1`, the other side's restriction must survive —
/// dropping it would silently turn a type-scoped rule into "all ICMP". The
/// domain has no separate type/code fields, so the restricted bound is
/// mapped as a single-value range (`n..n`), losing only the "any code"
/// breadth, never the type restriction itself.
pub(crate) fn build_port_range(
    resource_id: &str,
    field: &'static str,
    protocol: &str,
    from_port: Option<i32>,
    to_port: Option<i32>,
) -> Result<Option<PortRange>, MappingError> {
    if protocol == "-1" {
        return Ok(None);
    }

    let (Some(from_port), Some(to_port)) = (from_port, to_port) else {
        return Ok(None);
    };

    let (from_port, to_port) = match (from_port < 0, to_port < 0) {
        (true, true) => return Ok(None),
        (true, false) => (to_port, to_port),
        (false, true) => (from_port, from_port),
        (false, false) => (from_port, to_port),
    };

    let to_u16 = |value: i32| {
        u16::try_from(value).map_err(|_| MappingError::InvalidField {
            resource_id: resource_id.to_string(),
            field,
            reason: format!("port {value} exceeds u16 range"),
        })
    };
    let from_port = to_u16(from_port)?;
    let to_port = to_u16(to_port)?;

    PortRange::new(from_port, to_port)
        .map(Some)
        .map_err(|source: RuleError| MappingError::InvalidField {
            resource_id: resource_id.to_string(),
            field,
            reason: source.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn build_port_range_icmp_type_with_any_code_preserves_type_restriction() {
        // Arrange
        let from_port = Some(8);
        let to_port = Some(-1);

        // Act
        let result = build_port_range("sg-0example", "port_range", "icmp", from_port, to_port)
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(result, PortRange::new(8, 8).ok());
    }

    #[test]
    fn build_port_range_icmp_any_type_with_code_preserves_code_restriction() {
        // Arrange
        let from_port = Some(-1);
        let to_port = Some(0);

        // Act
        let result = build_port_range("sg-0example", "port_range", "icmp", from_port, to_port)
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(result, PortRange::new(0, 0).ok());
    }

    #[test]
    fn build_port_range_icmp_any_type_any_code_normalizes_to_none() {
        // Arrange
        let from_port = Some(-1);
        let to_port = Some(-1);

        // Act
        let result = build_port_range("sg-0example", "port_range", "icmp", from_port, to_port)
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(result, None);
    }
}
