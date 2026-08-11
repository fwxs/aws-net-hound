//! Maps `aws_sdk_ec2::types::*` values into `core::domain` rule types.
//!
//! The SDK types and the domain types disagree on purpose: `IpPermission`
//! is a bag of `Option`s that can carry a CIDR and an SG reference at once,
//! while `SgRule::target` is an enum that forces a choice. This module is
//! where that shape mismatch gets resolved.

pub mod nacl;
pub mod sg;

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
/// circuits to `None` regardless of what `from_port`/`to_port` contain. A
/// negative `from_port`/`to_port` (AWS's per-port "-1" sentinel, e.g. "all
/// ICMP types") likewise means "no specific port", not a port value, and
/// also normalises to `None`. Both cases exist so the magic `-1` never
/// survives into the domain type as a literal port number.
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

    if from_port < 0 || to_port < 0 {
        return Ok(None);
    }

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
