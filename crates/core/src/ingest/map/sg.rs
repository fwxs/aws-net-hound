//! Maps `aws_sdk_ec2::types::SecurityGroup` into `core::domain::rule::SgRule`.

use aws_sdk_ec2::types::{IpPermission, SecurityGroup};

use crate::domain::rule::{Direction, RuleTarget, SgRule};
use crate::error::MappingError;

use super::{build_port_range, require_str};

/// Maps a security group's ingress and egress permissions into `SgRule`s.
///
/// Fans each `IpPermission` out into one `SgRule` per target: an entry in
/// `ip_ranges`/`ipv6_ranges` becomes a CIDR-targeted rule, an entry in
/// `user_id_group_pairs` becomes an SG-reference-targeted rule. A single
/// permission carrying both never collapses into one ambiguous rule.
///
/// A `UserIdGroupPair` whose `user_id` differs from `current_account_id` is
/// a cross-account reference that cannot be dereferenced with
/// single-account credentials: it is emitted with `resolved: false` and
/// `Ok`, never dropped and never an `Err` — dereferencing it is a later
/// milestone's job (the `Resolver` trait), not this mapper's.
///
/// # Example
///
/// ```
/// use aws_net_hound_core::ingest::map::sg::map_security_group_rules;
/// use aws_sdk_ec2::types::SecurityGroup;
///
/// let sg = SecurityGroup::builder().group_id("sg-0example").build();
/// let rules = map_security_group_rules(&sg, "123456789012").unwrap();
/// assert!(rules.is_empty());
/// ```
pub fn map_security_group_rules(
    sg: &SecurityGroup,
    current_account_id: &str,
) -> Result<Vec<SgRule>, MappingError> {
    let group_id = require_str("<unknown security group>", "group_id", &sg.group_id)?.to_string();

    let mut rules = Vec::new();
    for permission in sg.ip_permissions() {
        rules.extend(map_permission(
            &group_id,
            permission,
            Direction::Ingress,
            current_account_id,
        )?);
    }
    for permission in sg.ip_permissions_egress() {
        rules.extend(map_permission(
            &group_id,
            permission,
            Direction::Egress,
            current_account_id,
        )?);
    }
    Ok(rules)
}

fn map_permission(
    group_id: &str,
    permission: &IpPermission,
    direction: Direction,
    current_account_id: &str,
) -> Result<Vec<SgRule>, MappingError> {
    let protocol = permission
        .ip_protocol
        .clone()
        .unwrap_or_else(|| "-1".to_string());
    let port_range = build_port_range(
        group_id,
        "port_range",
        &protocol,
        permission.from_port,
        permission.to_port,
    )?;

    let mut rules = Vec::with_capacity(
        permission.ip_ranges().len()
            + permission.ipv6_ranges().len()
            + permission.user_id_group_pairs().len(),
    );

    for ip_range in permission.ip_ranges() {
        let cidr = require_str(group_id, "ip_ranges[].cidr_ip", &ip_range.cidr_ip)?.to_string();
        rules.push(SgRule {
            direction,
            protocol: protocol.clone(),
            port_range,
            target: RuleTarget::Cidr { cidr },
            resolved: true,
        });
    }

    for ipv6_range in permission.ipv6_ranges() {
        let cidr =
            require_str(group_id, "ipv6_ranges[].cidr_ipv6", &ipv6_range.cidr_ipv6)?.to_string();
        rules.push(SgRule {
            direction,
            protocol: protocol.clone(),
            port_range,
            target: RuleTarget::Cidr { cidr },
            resolved: true,
        });
    }

    for pair in permission.user_id_group_pairs() {
        let security_group_id =
            require_str(group_id, "user_id_group_pairs[].group_id", &pair.group_id)?.to_string();
        // Absent `user_id` means the SDK didn't echo an owner back; treat
        // that as same-account rather than as an unresolvable reference.
        let resolved = pair
            .user_id
            .as_deref()
            .is_none_or(|owner_id| owner_id == current_account_id);
        rules.push(SgRule {
            direction,
            protocol: protocol.clone(),
            port_range,
            target: RuleTarget::SecurityGroupRef { security_group_id },
            resolved,
        });
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use aws_sdk_ec2::types::{IpRange, SecurityGroup, UserIdGroupPair};
    use pretty_assertions::assert_eq;

    use super::*;

    const CURRENT_ACCOUNT_ID: &str = "123456789012";
    const OTHER_ACCOUNT_ID: &str = "999999999999";

    fn permission_builder() -> aws_sdk_ec2::types::builders::IpPermissionBuilder {
        IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(443)
            .to_port(443)
    }

    #[test]
    fn map_security_group_rules_permission_with_cidr_and_sg_ref_returns_two_rules() {
        // Arrange
        let permission = permission_builder()
            .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
            .user_id_group_pairs(
                UserIdGroupPair::builder()
                    .group_id("sg-0example")
                    .user_id(CURRENT_ACCOUNT_ID)
                    .build(),
            )
            .build();
        let sg = SecurityGroup::builder()
            .group_id("sg-0source")
            .ip_permissions(permission)
            .build();

        // Act
        let rules = map_security_group_rules(&sg, CURRENT_ACCOUNT_ID)
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules.len(), 2);
        assert!(matches!(rules[0].target, RuleTarget::Cidr { .. }));
        assert!(matches!(
            rules[1].target,
            RuleTarget::SecurityGroupRef { .. }
        ));
    }

    #[test]
    fn map_security_group_rules_cross_account_reference_returns_ok_with_resolved_false() {
        // Arrange
        let permission = permission_builder()
            .user_id_group_pairs(
                UserIdGroupPair::builder()
                    .group_id("sg-0example")
                    .user_id(OTHER_ACCOUNT_ID)
                    .build(),
            )
            .build();
        let sg = SecurityGroup::builder()
            .group_id("sg-0source")
            .ip_permissions(permission)
            .build();

        // Act
        let rules = map_security_group_rules(&sg, CURRENT_ACCOUNT_ID)
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].resolved, false);
    }

    #[test]
    fn map_security_group_rules_same_account_reference_returns_resolved_true() {
        // Arrange
        let permission = permission_builder()
            .user_id_group_pairs(
                UserIdGroupPair::builder()
                    .group_id("sg-0example")
                    .user_id(CURRENT_ACCOUNT_ID)
                    .build(),
            )
            .build();
        let sg = SecurityGroup::builder()
            .group_id("sg-0source")
            .ip_permissions(permission)
            .build();

        // Act
        let rules = map_security_group_rules(&sg, CURRENT_ACCOUNT_ID)
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].resolved, true);
    }

    #[test]
    fn map_security_group_rules_absent_owner_id_treated_as_same_account() {
        // Arrange
        let permission = permission_builder()
            .user_id_group_pairs(UserIdGroupPair::builder().group_id("sg-0example").build())
            .build();
        let sg = SecurityGroup::builder()
            .group_id("sg-0source")
            .ip_permissions(permission)
            .build();

        // Act
        let rules = map_security_group_rules(&sg, CURRENT_ACCOUNT_ID)
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].resolved, true);
    }

    #[test]
    fn map_security_group_rules_protocol_minus_one_normalizes_to_all_protocols() {
        // Arrange
        let permission = IpPermission::builder()
            .ip_protocol("-1")
            .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
            .build();
        let sg = SecurityGroup::builder()
            .group_id("sg-0source")
            .ip_permissions(permission)
            .build();

        // Act
        let rules = map_security_group_rules(&sg, CURRENT_ACCOUNT_ID)
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].protocol, "-1");
        assert_eq!(rules[0].port_range, None);
    }

    #[test]
    fn map_security_group_rules_inverted_port_range_returns_mapping_error() {
        // Arrange
        let permission = IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(443)
            .to_port(80)
            .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
            .build();
        let sg = SecurityGroup::builder()
            .group_id("sg-0source")
            .ip_permissions(permission)
            .build();

        // Act
        let result = map_security_group_rules(&sg, CURRENT_ACCOUNT_ID);

        // Assert
        assert!(matches!(result, Err(MappingError::InvalidField { .. })));
    }
}
