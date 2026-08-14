//! Maps the five raw EC2 `Describe*` collections into a `GraphBatch` —
//! every node and edge `crates/core/docs/schema.md` calls "topology", plus
//! the `ALLOWS_INGRESS`/`ALLOWS_EGRESS`/`HAS_RULE` rule edges attached to
//! their owning resource.
//!
//! `VPC` and `Subnet` nodes are synthesized from `vpc_id`/`subnet_id`
//! sightings on the other five resource types rather than sourced from a
//! `DescribeVpcs`/`DescribeSubnets` call — no such collector exists yet, so
//! `cidr_block`/`availability_zone` are emitted as empty strings. See
//! `schema.md`'s `VPC`/`Subnet` sections for this documented gap.

use std::collections::BTreeMap;

use aws_sdk_ec2::types::{
    NetworkAcl, NetworkInterface, Route, RouteTable, SecurityGroup, VpcPeeringConnection,
};

use crate::domain::rule::Direction;
use crate::error::MappingError;
use crate::graph::model::{Edge, GraphBatch};
use crate::ports::{
    EniRecord, HasSgEdge, InSubnetEdge, NetworkAclRecord, ProtectedByEdge, RouteTableRecord,
    RoutesToEdge, SecurityGroupRecord, SubnetRecord, UsesRouteTableEdge, VpcRecord,
};

use super::nacl::map_network_acl_rules;
use super::require_str;
use super::sg::map_security_group_rules;

/// Builds a [`GraphBatch`] from the five raw EC2 collections
/// (`crate::ingest::collect`), deduplicating `VPC`/`Subnet` nodes by AWS id
/// and deriving every topology and rule edge, each at exactly one place in
/// this module.
///
/// `account_id` is stamped on every node record and passed through to
/// [`map_security_group_rules`] for its own cross-account resolution.
///
/// # Example
///
/// ```
/// use aws_net_hound_core::ingest::map::topology::build_graph_batch;
///
/// let batch = build_graph_batch("123456789012", &[], &[], &[], &[], &[]).unwrap();
/// assert!(batch.edges.is_empty());
/// ```
pub fn build_graph_batch(
    account_id: &str,
    security_groups: &[SecurityGroup],
    network_acls: &[NetworkAcl],
    route_tables: &[RouteTable],
    network_interfaces: &[NetworkInterface],
    vpc_peering_connections: &[VpcPeeringConnection],
) -> Result<GraphBatch, MappingError> {
    let enis = network_interfaces
        .iter()
        .map(|eni| map_eni_node(eni, account_id))
        .collect::<Result<Vec<_>, _>>()?;

    let security_group_records = security_groups
        .iter()
        .map(|sg| map_security_group_node(sg, account_id))
        .collect::<Result<Vec<_>, _>>()?;

    let network_acl_records = network_acls
        .iter()
        .map(|acl| map_network_acl_node(acl, account_id))
        .collect::<Result<Vec<_>, _>>()?;

    let route_table_records = route_tables
        .iter()
        .map(|route_table| map_route_table_node(route_table, account_id))
        .collect::<Result<Vec<_>, _>>()?;

    let vpcs = collect_vpc_stubs(
        account_id,
        security_groups,
        network_acls,
        route_tables,
        network_interfaces,
        vpc_peering_connections,
    )
    .into_values()
    .collect();

    let subnets = collect_subnet_stubs(account_id, network_interfaces, network_acls, route_tables)
        .into_values()
        .collect();

    // Every `*_edges` helper below is handed the node records built above
    // instead of re-deriving/re-validating each id from the raw SDK type:
    // `map_eni_node`/etc. already validated it once, and `zip`ping is sound
    // because each `Vec` of records was built via a straight, unfiltered
    // `.map()` over its corresponding raw slice — same length, same order.
    let mut edges = has_sg_edges(network_interfaces, &enis)?;
    edges.extend(in_subnet_edges(&enis));
    edges.extend(protected_by_edges(network_acls, &network_acl_records));
    edges.extend(uses_route_table_edges(route_tables, &route_table_records));
    edges.extend(routes_to_edges(
        account_id,
        route_tables,
        &route_table_records,
        vpc_peering_connections,
    ));
    edges.extend(allows_edges(
        security_groups,
        &security_group_records,
        account_id,
    )?);
    edges.extend(has_rule_edges(network_acls, &network_acl_records)?);

    Ok(GraphBatch {
        enis,
        security_groups: security_group_records,
        network_acls: network_acl_records,
        subnets,
        vpcs,
        route_tables: route_table_records,
        edges,
    })
}

pub(crate) fn map_eni_node(
    eni: &NetworkInterface,
    account_id: &str,
) -> Result<EniRecord, MappingError> {
    let id = require_str(
        "<unknown ENI>",
        "network_interface_id",
        &eni.network_interface_id,
    )?
    .to_string();
    let vpc_id = require_str(&id, "vpc_id", &eni.vpc_id)?.to_string();
    let subnet_id = require_str(&id, "subnet_id", &eni.subnet_id)?.to_string();
    let private_ip = require_str(&id, "private_ip_address", &eni.private_ip_address)?.to_string();

    Ok(EniRecord {
        id,
        account_id: account_id.to_string(),
        vpc_id,
        subnet_id,
        private_ip,
        description: eni.description.clone(),
    })
}

pub(crate) fn map_security_group_node(
    sg: &SecurityGroup,
    account_id: &str,
) -> Result<SecurityGroupRecord, MappingError> {
    let id = require_str("<unknown security group>", "group_id", &sg.group_id)?.to_string();
    let vpc_id = require_str(&id, "vpc_id", &sg.vpc_id)?.to_string();
    let name = require_str(&id, "group_name", &sg.group_name)?.to_string();

    Ok(SecurityGroupRecord {
        id,
        account_id: account_id.to_string(),
        vpc_id,
        name,
        description: sg.description.clone(),
    })
}

pub(crate) fn map_network_acl_node(
    acl: &NetworkAcl,
    account_id: &str,
) -> Result<NetworkAclRecord, MappingError> {
    let id = require_str(
        "<unknown network acl>",
        "network_acl_id",
        &acl.network_acl_id,
    )?
    .to_string();
    let vpc_id = require_str(&id, "vpc_id", &acl.vpc_id)?.to_string();
    let is_default = acl.is_default.ok_or_else(|| MappingError::InvalidField {
        resource_id: id.clone(),
        field: "is_default",
        reason: "field is required but absent".to_string(),
    })?;

    Ok(NetworkAclRecord {
        id,
        account_id: account_id.to_string(),
        vpc_id,
        is_default,
    })
}

pub(crate) fn map_route_table_node(
    route_table: &RouteTable,
    account_id: &str,
) -> Result<RouteTableRecord, MappingError> {
    let id = require_str(
        "<unknown route table>",
        "route_table_id",
        &route_table.route_table_id,
    )?
    .to_string();
    let vpc_id = require_str(&id, "vpc_id", &route_table.vpc_id)?.to_string();
    let is_main = route_table
        .associations()
        .iter()
        .any(|association| association.main == Some(true));

    Ok(RouteTableRecord {
        id,
        account_id: account_id.to_string(),
        vpc_id,
        is_main,
    })
}

/// `HAS_SG`: sole source of truth is `NetworkInterface.groups`. `enis` is
/// `network_interfaces` mapped 1:1 through [`map_eni_node`] — zipping reuses
/// each ENI's already-validated id instead of re-validating it here.
fn has_sg_edges(
    network_interfaces: &[NetworkInterface],
    enis: &[EniRecord],
) -> Result<Vec<Edge>, MappingError> {
    network_interfaces
        .iter()
        .zip(enis)
        .map(|(eni, record)| {
            eni.groups()
                .iter()
                .map(|group| {
                    let security_group_id =
                        require_str(&record.id, "groups[].group_id", &group.group_id)?.to_string();
                    Ok(Edge::HasSg(HasSgEdge {
                        eni_id: record.id.clone(),
                        security_group_id,
                    }))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<Vec<_>>, _>>()
        .map(|nested| nested.into_iter().flatten().collect())
}

/// `IN_SUBNET`: sole source of truth is `NetworkInterface.subnet_id`,
/// already carried on each already-validated [`EniRecord`] — no raw SDK
/// access or re-validation needed here.
fn in_subnet_edges(enis: &[EniRecord]) -> Vec<Edge> {
    enis.iter()
        .map(|eni| {
            Edge::InSubnet(InSubnetEdge {
                eni_id: eni.id.clone(),
                subnet_id: eni.subnet_id.clone(),
            })
        })
        .collect()
}

/// `PROTECTED_BY`: sole source of truth is `NetworkAcl.associations[].subnet_id`.
/// `network_acl_records` is `network_acls` mapped 1:1 through
/// [`map_network_acl_node`] — zipping reuses each ACL's already-validated id.
fn protected_by_edges(
    network_acls: &[NetworkAcl],
    network_acl_records: &[NetworkAclRecord],
) -> Vec<Edge> {
    network_acls
        .iter()
        .zip(network_acl_records)
        .flat_map(|(acl, record)| {
            acl.associations().iter().filter_map(move |association| {
                association.subnet_id.clone().map(|subnet_id| {
                    Edge::ProtectedBy(ProtectedByEdge {
                        subnet_id,
                        network_acl_id: record.id.clone(),
                    })
                })
            })
        })
        .collect()
}

/// `USES_ROUTE_TABLE`: sole source of truth is
/// `RouteTable.associations[].subnet_id`. An association with no `subnet_id`
/// is AWS's implicit main-table association (no concrete subnet to key the
/// edge on) — it emits no edge here. The route table is not dropped: its
/// `is_main` flag (set in [`map_route_table_node`]) records the fact on the
/// node itself. See `schema.md`'s `ROUTES_TO` footnote. `route_table_records`
/// is `route_tables` mapped 1:1 through [`map_route_table_node`] — zipping
/// reuses each route table's already-validated id.
fn uses_route_table_edges(
    route_tables: &[RouteTable],
    route_table_records: &[RouteTableRecord],
) -> Vec<Edge> {
    route_tables
        .iter()
        .zip(route_table_records)
        .flat_map(|(route_table, record)| {
            route_table
                .associations()
                .iter()
                .filter_map(move |association| {
                    association.subnet_id.clone().map(|subnet_id| {
                        Edge::UsesRouteTable(UsesRouteTableEdge {
                            subnet_id,
                            route_table_id: record.id.clone(),
                        })
                    })
                })
        })
        .collect()
}

/// `ROUTES_TO`: sole source of truth is `RouteTable.routes[]`. A route with
/// neither `destination_cidr_block` nor `destination_ipv6_cidr_block` (e.g.
/// a `destination_prefix_list_id`-only endpoint route) has no CIDR to key
/// the edge's required `destination_cidr` on and is skipped — documented in
/// `schema.md`. `route_table_records` is `route_tables` mapped 1:1 through
/// [`map_route_table_node`] — zipping reuses each route table's
/// already-validated id and `vpc_id`.
fn routes_to_edges(
    account_id: &str,
    route_tables: &[RouteTable],
    route_table_records: &[RouteTableRecord],
    peerings: &[VpcPeeringConnection],
) -> Vec<Edge> {
    route_tables
        .iter()
        .zip(route_table_records)
        .flat_map(|(route_table, record)| {
            route_table.routes().iter().filter_map(move |route| {
                let destination_cidr = route
                    .destination_cidr_block
                    .clone()
                    .or_else(|| route.destination_ipv6_cidr_block.clone())?;

                let (target_vpc_id, resolved) =
                    resolve_route_target(account_id, &record.vpc_id, route, peerings);

                Some(Edge::RoutesTo(RoutesToEdge {
                    route_table_id: record.id.clone(),
                    destination_cidr,
                    target_vpc_id,
                    resolved,
                }))
            })
        })
        .collect()
}

/// Resolves a single route's target: `"local"` gateway resolves to the
/// route table's own VPC; a peering connection resolves to the peering's
/// other-side VPC only when that side is owned by `account_id` (mirrors
/// M1-T3's cross-account `resolved: false`, never dropped); every other
/// target (IGW/NAT/instance/ENI/transit gateway) is out of scope for node
/// modeling this milestone.
fn resolve_route_target(
    account_id: &str,
    rt_vpc_id: &str,
    route: &Route,
    peerings: &[VpcPeeringConnection],
) -> (Option<String>, bool) {
    if route.gateway_id.as_deref() == Some("local") {
        return (Some(rt_vpc_id.to_string()), true);
    }

    let Some(pcx_id) = route.vpc_peering_connection_id.as_deref() else {
        return (None, false);
    };

    let other_side = peerings
        .iter()
        .find(|pcx| pcx.vpc_peering_connection_id.as_deref() == Some(pcx_id))
        .and_then(|pcx| {
            [
                pcx.requester_vpc_info.as_ref(),
                pcx.accepter_vpc_info.as_ref(),
            ]
            .into_iter()
            .flatten()
            .find(|info| info.vpc_id.as_deref() != Some(rt_vpc_id))
        });

    match other_side {
        Some(info) if info.owner_id.as_deref() == Some(account_id) => match info.vpc_id.clone() {
            Some(vpc_id) => (Some(vpc_id), true),
            None => (None, false),
        },
        _ => (None, false),
    }
}

/// `ALLOWS_INGRESS`/`ALLOWS_EGRESS`: sole source of truth is
/// [`map_security_group_rules`] (M1-T3). `security_group_records` is
/// `security_groups` mapped 1:1 through [`map_security_group_node`] —
/// zipping reuses each SG's already-validated id.
fn allows_edges(
    security_groups: &[SecurityGroup],
    security_group_records: &[SecurityGroupRecord],
    account_id: &str,
) -> Result<Vec<Edge>, MappingError> {
    security_groups
        .iter()
        .zip(security_group_records)
        .map(|(sg, record)| {
            map_security_group_rules(sg, account_id).map(|rules| {
                rules
                    .into_iter()
                    .map(|rule| match rule.direction {
                        Direction::Ingress => Edge::AllowsIngress {
                            security_group_id: record.id.clone(),
                            rule,
                        },
                        Direction::Egress => Edge::AllowsEgress {
                            security_group_id: record.id.clone(),
                            rule,
                        },
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Result<Vec<Vec<_>>, _>>()
        .map(|nested| nested.into_iter().flatten().collect())
}

/// `HAS_RULE`: sole source of truth is [`map_network_acl_rules`] (M1-T3).
/// `network_acl_records` is `network_acls` mapped 1:1 through
/// [`map_network_acl_node`] — zipping reuses each ACL's already-validated id.
fn has_rule_edges(
    network_acls: &[NetworkAcl],
    network_acl_records: &[NetworkAclRecord],
) -> Result<Vec<Edge>, MappingError> {
    network_acls
        .iter()
        .zip(network_acl_records)
        .map(|(acl, record)| {
            map_network_acl_rules(acl).map(|rules| {
                rules
                    .into_iter()
                    .map(|rule| Edge::HasRule {
                        network_acl_id: record.id.clone(),
                        rule,
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Result<Vec<Vec<_>>, _>>()
        .map(|nested| nested.into_iter().flatten().collect())
}

fn insert_vpc_stub(vpcs: &mut BTreeMap<String, VpcRecord>, account_id: &str, vpc_id: String) {
    vpcs.entry(vpc_id.clone()).or_insert_with(|| VpcRecord {
        id: vpc_id,
        account_id: account_id.to_string(),
        cidr_block: String::new(),
    });
}

/// Synthesizes `VPC` node stubs from `vpc_id` sightings across every
/// collector response, since no `DescribeVpcs` collector exists yet — see
/// this module's doc comment and `schema.md`'s `VPC` section.
///
/// A cross-account peering counterpart VPC (`owner_id != account_id`) gets
/// no stub: it isn't in the audited account, and stamping `account_id` on a
/// VPC the account doesn't own would be actively wrong, not just
/// incomplete.
fn collect_vpc_stubs(
    account_id: &str,
    security_groups: &[SecurityGroup],
    network_acls: &[NetworkAcl],
    route_tables: &[RouteTable],
    network_interfaces: &[NetworkInterface],
    peerings: &[VpcPeeringConnection],
) -> BTreeMap<String, VpcRecord> {
    let mut vpcs = BTreeMap::new();

    let sighted_vpc_ids = security_groups
        .iter()
        .map(|sg| &sg.vpc_id)
        .chain(network_acls.iter().map(|acl| &acl.vpc_id))
        .chain(route_tables.iter().map(|route_table| &route_table.vpc_id))
        .chain(network_interfaces.iter().map(|eni| &eni.vpc_id))
        .flatten();
    for vpc_id in sighted_vpc_ids {
        insert_vpc_stub(&mut vpcs, account_id, vpc_id.clone());
    }

    for peering in peerings {
        let sides = [
            peering.requester_vpc_info.as_ref(),
            peering.accepter_vpc_info.as_ref(),
        ];
        for info in sides.into_iter().flatten() {
            if info.owner_id.as_deref() == Some(account_id) {
                if let Some(vpc_id) = info.vpc_id.clone() {
                    insert_vpc_stub(&mut vpcs, account_id, vpc_id);
                }
            }
        }
    }

    vpcs
}

fn insert_subnet_stub(
    subnets: &mut BTreeMap<String, SubnetRecord>,
    account_id: &str,
    subnet_id: String,
    vpc_id: String,
) {
    subnets
        .entry(subnet_id.clone())
        .or_insert_with(|| SubnetRecord {
            id: subnet_id,
            account_id: account_id.to_string(),
            vpc_id,
            cidr_block: String::new(),
            availability_zone: String::new(),
        });
}

/// Synthesizes `Subnet` node stubs from `subnet_id` sightings, pairing each
/// with the owning resource's own `vpc_id` — AWS guarantees a NACL/route
/// table/ENI's `vpc_id` matches its associated subnet's VPC, so `vpc_id` is
/// not part of the "no data source" gap, unlike `cidr_block`/
/// `availability_zone`. See this module's doc comment and `schema.md`'s
/// `Subnet` section.
fn collect_subnet_stubs(
    account_id: &str,
    network_interfaces: &[NetworkInterface],
    network_acls: &[NetworkAcl],
    route_tables: &[RouteTable],
) -> BTreeMap<String, SubnetRecord> {
    let mut subnets = BTreeMap::new();

    for eni in network_interfaces {
        if let (Some(subnet_id), Some(vpc_id)) = (eni.subnet_id.clone(), eni.vpc_id.clone()) {
            insert_subnet_stub(&mut subnets, account_id, subnet_id, vpc_id);
        }
    }

    for acl in network_acls {
        let Some(vpc_id) = acl.vpc_id.clone() else {
            continue;
        };
        for association in acl.associations() {
            if let Some(subnet_id) = association.subnet_id.clone() {
                insert_subnet_stub(&mut subnets, account_id, subnet_id, vpc_id.clone());
            }
        }
    }

    for route_table in route_tables {
        let Some(vpc_id) = route_table.vpc_id.clone() else {
            continue;
        };
        for association in route_table.associations() {
            if let Some(subnet_id) = association.subnet_id.clone() {
                insert_subnet_stub(&mut subnets, account_id, subnet_id, vpc_id.clone());
            }
        }
    }

    subnets
}

#[cfg(test)]
mod tests {
    use aws_sdk_ec2::types::{
        GroupIdentifier, NetworkAclAssociation, NetworkAclEntry, RouteTableAssociation, RuleAction,
        VpcPeeringConnectionVpcInfo,
    };
    use pretty_assertions::assert_eq;

    use super::*;

    const ACCOUNT_ID: &str = "123456789012";
    const OTHER_ACCOUNT_ID: &str = "999999999999";

    fn eni_builder() -> aws_sdk_ec2::types::builders::NetworkInterfaceBuilder {
        NetworkInterface::builder()
            .network_interface_id("eni-1")
            .vpc_id("vpc-1")
            .subnet_id("subnet-1")
            .private_ip_address("10.0.0.5")
    }

    #[test]
    fn build_graph_batch_eni_with_two_groups_emits_two_has_sg_edges() {
        // Arrange
        let eni = eni_builder()
            .groups(GroupIdentifier::builder().group_id("sg-1").build())
            .groups(GroupIdentifier::builder().group_id("sg-2").build())
            .build();

        // Act
        let batch = build_graph_batch(ACCOUNT_ID, &[], &[], &[], &[eni], &[])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        let has_sg_ids: Vec<&str> = batch
            .edges
            .iter()
            .filter_map(|edge| match edge {
                Edge::HasSg(edge) => Some(edge.security_group_id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(has_sg_ids, vec!["sg-1", "sg-2"]);
    }

    #[test]
    fn build_graph_batch_eni_emits_in_subnet_edge() {
        // Arrange
        let eni = eni_builder().build();

        // Act
        let batch = build_graph_batch(ACCOUNT_ID, &[], &[], &[], &[eni], &[])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert!(batch.edges.contains(&Edge::InSubnet(InSubnetEdge {
            eni_id: "eni-1".to_string(),
            subnet_id: "subnet-1".to_string(),
        })));
    }

    #[test]
    fn build_graph_batch_nacl_association_emits_protected_by_edge() {
        // Arrange
        let acl = NetworkAcl::builder()
            .network_acl_id("acl-1")
            .vpc_id("vpc-1")
            .is_default(false)
            .associations(
                NetworkAclAssociation::builder()
                    .network_acl_id("acl-1")
                    .subnet_id("subnet-1")
                    .build(),
            )
            .build();

        // Act
        let batch = build_graph_batch(ACCOUNT_ID, &[], &[acl], &[], &[], &[])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert!(batch.edges.contains(&Edge::ProtectedBy(ProtectedByEdge {
            subnet_id: "subnet-1".to_string(),
            network_acl_id: "acl-1".to_string(),
        })));
    }

    #[test]
    fn build_graph_batch_route_table_association_emits_uses_route_table_edge() {
        // Arrange
        let route_table = RouteTable::builder()
            .route_table_id("rtb-1")
            .vpc_id("vpc-1")
            .associations(
                RouteTableAssociation::builder()
                    .main(false)
                    .subnet_id("subnet-1")
                    .build(),
            )
            .build();

        // Act
        let batch = build_graph_batch(ACCOUNT_ID, &[], &[], &[route_table], &[], &[])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert!(batch
            .edges
            .contains(&Edge::UsesRouteTable(UsesRouteTableEdge {
                subnet_id: "subnet-1".to_string(),
                route_table_id: "rtb-1".to_string(),
            })));
    }

    #[test]
    fn build_graph_batch_main_route_table_without_association_is_recorded_not_dropped() {
        // Arrange
        let route_table = RouteTable::builder()
            .route_table_id("rtb-1")
            .vpc_id("vpc-1")
            .associations(RouteTableAssociation::builder().main(true).build())
            .build();

        // Act
        let batch = build_graph_batch(ACCOUNT_ID, &[], &[], &[route_table], &[], &[])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(batch.route_tables.len(), 1);
        assert!(batch.route_tables[0].is_main);
        assert!(!batch.edges.iter().any(
            |edge| matches!(edge, Edge::UsesRouteTable(edge) if edge.route_table_id == "rtb-1")
        ));
    }

    #[test]
    fn build_graph_batch_route_to_peering_in_other_account_marks_resolved_false() {
        // Arrange
        let route_table = RouteTable::builder()
            .route_table_id("rtb-1")
            .vpc_id("vpc-a")
            .routes(
                Route::builder()
                    .destination_cidr_block("10.0.0.0/16")
                    .vpc_peering_connection_id("pcx-1")
                    .build(),
            )
            .build();
        let peering = VpcPeeringConnection::builder()
            .vpc_peering_connection_id("pcx-1")
            .requester_vpc_info(
                VpcPeeringConnectionVpcInfo::builder()
                    .vpc_id("vpc-a")
                    .owner_id(ACCOUNT_ID)
                    .build(),
            )
            .accepter_vpc_info(
                VpcPeeringConnectionVpcInfo::builder()
                    .vpc_id("vpc-b")
                    .owner_id(OTHER_ACCOUNT_ID)
                    .build(),
            )
            .build();

        // Act
        let batch = build_graph_batch(ACCOUNT_ID, &[], &[], &[route_table], &[], &[peering])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        let routes_to = batch
            .edges
            .iter()
            .find_map(|edge| match edge {
                Edge::RoutesTo(edge) => Some(edge),
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected a RoutesTo edge in {:?}", batch.edges));
        assert!(!routes_to.resolved);
        assert_eq!(routes_to.target_vpc_id, None);
    }

    #[test]
    fn build_graph_batch_vpc_seen_in_multiple_responses_is_deduplicated() {
        // Arrange
        let sg = SecurityGroup::builder()
            .group_id("sg-1")
            .vpc_id("vpc-1")
            .group_name("sg")
            .build();
        let acl = NetworkAcl::builder()
            .network_acl_id("acl-1")
            .vpc_id("vpc-1")
            .is_default(false)
            .build();

        // Act
        let batch = build_graph_batch(ACCOUNT_ID, &[sg], &[acl], &[], &[], &[])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(batch.vpcs.len(), 1);
        assert_eq!(batch.vpcs[0].id, "vpc-1");
    }

    #[test]
    fn build_graph_batch_nacl_rules_carry_rule_number_on_has_rule_edge() {
        // Arrange
        let entry_builder = |rule_number: i32| {
            NetworkAclEntry::builder()
                .rule_number(rule_number)
                .protocol("tcp")
                .cidr_block("0.0.0.0/0")
                .egress(false)
                .rule_action(RuleAction::Allow)
        };
        let acl = NetworkAcl::builder()
            .network_acl_id("acl-1")
            .vpc_id("vpc-1")
            .is_default(false)
            .entries(entry_builder(100).build())
            .entries(entry_builder(200).build())
            .build();

        // Act
        let batch = build_graph_batch(ACCOUNT_ID, &[], &[acl], &[], &[], &[])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        let mut rule_numbers: Vec<u16> = batch
            .edges
            .iter()
            .filter_map(|edge| match edge {
                Edge::HasRule { rule, .. } => Some(rule.rule_number),
                _ => None,
            })
            .collect();
        rule_numbers.sort_unstable();
        assert_eq!(rule_numbers, vec![100, 200]);
    }

    #[test]
    fn build_graph_batch_empty_inputs_returns_empty_batch() {
        // Arrange / Act
        let batch = build_graph_batch(ACCOUNT_ID, &[], &[], &[], &[], &[])
            .unwrap_or_else(|error| panic!("expected Ok: {error}"));

        // Assert
        assert_eq!(batch, GraphBatch::default());
    }
}
