//! Maps `aws_sdk_ec2::types::NetworkAcl` into `core::domain::rule::NaclRule`.

use aws_sdk_ec2::types::{NetworkAcl, RuleAction};

use crate::domain::rule::{Action, Direction, NaclRule};
use crate::error::MappingError;

use super::{build_port_range, require_str};

/// Maps a network ACL's entries into `NaclRule`s.
///
/// NACL evaluation is first-match by ascending `rule_number`, and the EC2
/// API does **not** guarantee entries come back in that order — the
/// returned `Vec` is sorted by `rule_number` ascending before it is
/// returned, and that sort is the contract callers rely on, not the API's
/// response order. AWS's `32767` catch-all entry is a normal rule and maps
/// like any other; it is not special-cased.
///
/// # Example
///
/// ```
/// use aws_net_hound_core::ingest::map::nacl::map_network_acl_rules;
/// use aws_sdk_ec2::types::NetworkAcl;
///
/// let acl = NetworkAcl::builder().network_acl_id("acl-0example").build();
/// let rules = map_network_acl_rules(&acl).unwrap();
/// assert!(rules.is_empty());
/// ```
pub fn map_network_acl_rules(acl: &NetworkAcl) -> Result<Vec<NaclRule>, MappingError> {
    let network_acl_id = require_str(
        "<unknown network acl>",
        "network_acl_id",
        &acl.network_acl_id,
    )?
    .to_string();

    let mut rules = Vec::with_capacity(acl.entries().len());
    for entry in acl.entries() {
        let rule_number = entry
            .rule_number
            .ok_or_else(|| MappingError::InvalidField {
                resource_id: network_acl_id.clone(),
                field: "rule_number",
                reason: "field is required but absent".to_string(),
            })?;
        let rule_number = u16::try_from(rule_number).map_err(|_| MappingError::InvalidField {
            resource_id: network_acl_id.clone(),
            field: "rule_number",
            reason: format!("rule_number {rule_number} exceeds u16 range"),
        })?;

        let protocol = entry.protocol.clone().unwrap_or_else(|| "-1".to_string());
        let port_range = build_port_range(
            &network_acl_id,
            "port_range",
            &protocol,
            entry.port_range.as_ref().and_then(|range| range.from),
            entry.port_range.as_ref().and_then(|range| range.to),
        )?;

        let cidr = entry
            .cidr_block
            .clone()
            .or_else(|| entry.ipv6_cidr_block.clone())
            .ok_or_else(|| MappingError::InvalidField {
                resource_id: network_acl_id.clone(),
                field: "cidr_block",
                reason: "field is required but absent".to_string(),
            })?;

        let direction = if entry.egress.unwrap_or(false) {
            Direction::Egress
        } else {
            Direction::Ingress
        };

        let action = match entry.rule_action {
            Some(RuleAction::Allow) => Action::Allow,
            Some(RuleAction::Deny) => Action::Deny,
            // `RuleAction` is AWS-owned and `#[non_exhaustive]`; any variant
            // besides Allow/Deny (including absent) is malformed input, not
            // a new evaluation outcome to guess at.
            _ => {
                return Err(MappingError::InvalidField {
                    resource_id: network_acl_id.clone(),
                    field: "rule_action",
                    reason: "field is required and must be allow or deny".to_string(),
                });
            }
        };

        rules.push(NaclRule {
            rule_number,
            direction,
            protocol,
            port_range,
            cidr,
            action,
        });
    }

    rules.sort_by_key(|rule| rule.rule_number);
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use aws_sdk_ec2::types::{NetworkAcl, NetworkAclEntry, PortRange as SdkPortRange};
    use pretty_assertions::assert_eq;

    use super::*;

    fn entry_builder(rule_number: i32) -> aws_sdk_ec2::types::builders::NetworkAclEntryBuilder {
        NetworkAclEntry::builder()
            .rule_number(rule_number)
            .protocol("tcp")
            .cidr_block("0.0.0.0/0")
            .egress(false)
            .rule_action(RuleAction::Allow)
    }

    #[test]
    fn map_network_acl_rules_response_out_of_numeric_order_returns_sorted_by_rule_number() {
        // Arrange
        let acl = NetworkAcl::builder()
            .network_acl_id("acl-0example")
            .entries(entry_builder(300).build())
            .entries(entry_builder(100).build())
            .entries(entry_builder(200).build())
            .build();

        // Act
        let rules =
            map_network_acl_rules(&acl).unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        let rule_numbers: Vec<u16> = rules.iter().map(|rule| rule.rule_number).collect();
        assert_eq!(rule_numbers, vec![100, 200, 300]);
    }

    #[test]
    fn map_network_acl_rules_preserves_rule_number_verbatim() {
        // Arrange
        let acl = NetworkAcl::builder()
            .network_acl_id("acl-0example")
            .entries(entry_builder(32767).build())
            .build();

        // Act
        let rules =
            map_network_acl_rules(&acl).unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules[0].rule_number, 32767);
    }

    #[test]
    fn map_network_acl_rules_deny_action_maps_to_deny_variant() {
        // Arrange
        let acl = NetworkAcl::builder()
            .network_acl_id("acl-0example")
            .entries(entry_builder(100).rule_action(RuleAction::Deny).build())
            .build();

        // Act
        let rules =
            map_network_acl_rules(&acl).unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules[0].action, Action::Deny);
    }

    #[test]
    fn map_network_acl_rules_egress_flag_maps_to_egress_direction() {
        // Arrange
        let acl = NetworkAcl::builder()
            .network_acl_id("acl-0example")
            .entries(entry_builder(100).egress(true).build())
            .build();

        // Act
        let rules =
            map_network_acl_rules(&acl).unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules[0].direction, Direction::Egress);
    }

    #[test]
    fn map_network_acl_rules_protocol_minus_one_normalizes_port_range_to_none() {
        // Arrange
        let acl = NetworkAcl::builder()
            .network_acl_id("acl-0example")
            .entries(
                entry_builder(100)
                    .protocol("-1")
                    .port_range(SdkPortRange::builder().from(0).to(65535).build())
                    .build(),
            )
            .build();

        // Act
        let rules =
            map_network_acl_rules(&acl).unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules[0].port_range, None);
    }
}
