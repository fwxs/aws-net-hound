//! Integration tests for [`aws_net_hound_core::ingest::pipeline::run_full_ingest`].
//!
//! Drives `run_full_ingest_with_client` (the client/account-id-injectable
//! seam behind the public `run_full_ingest`) with `aws-smithy-mocks` for the
//! AWS boundary and `tests/common`'s in-memory `GraphWriter`, so the whole
//! pipeline runs with no AWS account, no network, and no Docker — plain
//! `cargo test --workspace`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use aws_net_hound_core::ingest::pipeline::run_full_ingest_with_client;
use aws_sdk_ec2::operation::describe_network_acls::DescribeNetworkAclsOutput;
use aws_sdk_ec2::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput;
use aws_sdk_ec2::operation::describe_route_tables::DescribeRouteTablesOutput;
use aws_sdk_ec2::operation::describe_security_groups::DescribeSecurityGroupsOutput;
use aws_sdk_ec2::operation::describe_vpc_peering_connections::DescribeVpcPeeringConnectionsOutput;
use aws_sdk_ec2::types::{GroupIdentifier, NetworkInterface, SecurityGroup};
use aws_sdk_ec2::Client;
use aws_smithy_mocks::{mock, Rule};
use common::{mock_ec2_client, InMemoryGraphWriter};
use pretty_assertions::assert_eq;

const ACCOUNT_ID: &str = "123456789012";

fn empty_security_groups_rule() -> Rule {
    mock!(Client::describe_security_groups)
        .then_output(|| DescribeSecurityGroupsOutput::builder().build())
}

fn empty_network_acls_rule() -> Rule {
    mock!(Client::describe_network_acls)
        .then_output(|| DescribeNetworkAclsOutput::builder().build())
}

fn empty_route_tables_rule() -> Rule {
    mock!(Client::describe_route_tables)
        .then_output(|| DescribeRouteTablesOutput::builder().build())
}

fn empty_network_interfaces_rule() -> Rule {
    mock!(Client::describe_network_interfaces)
        .then_output(|| DescribeNetworkInterfacesOutput::builder().build())
}

fn empty_vpc_peering_connections_rule() -> Rule {
    mock!(Client::describe_vpc_peering_connections)
        .then_output(|| DescribeVpcPeeringConnectionsOutput::builder().build())
}

#[tokio::test]
async fn run_full_ingest_empty_account_returns_zero_counts_not_error() {
    // Arrange
    let rules = [
        empty_security_groups_rule(),
        empty_network_acls_rule(),
        empty_route_tables_rule(),
        empty_network_interfaces_rule(),
        empty_vpc_peering_connections_rule(),
    ];
    let rule_refs: Vec<&Rule> = rules.iter().collect();
    let client = mock_ec2_client(&rule_refs);
    let writer = InMemoryGraphWriter::default();

    // Act
    let result = run_full_ingest_with_client(&client, ACCOUNT_ID, &writer).await;

    // Assert
    let report = match result {
        Ok(report) => report,
        Err(err) => panic!("expected an empty account to succeed, got {err:?}"),
    };
    assert!(report.counts.values().all(|count| *count == 0));
    assert_eq!(report.unresolved_references, 0);
    assert!(report.non_fatal.is_empty());
}

#[tokio::test]
async fn run_full_ingest_with_mocked_responses_returns_expected_counts_per_type() {
    // Arrange
    let sg_rule = mock!(Client::describe_security_groups).then_output(|| {
        DescribeSecurityGroupsOutput::builder()
            .security_groups(
                SecurityGroup::builder()
                    .group_id("sg-1")
                    .vpc_id("vpc-1")
                    .group_name("sg")
                    .build(),
            )
            .build()
    });
    let eni_rule = mock!(Client::describe_network_interfaces).then_output(|| {
        DescribeNetworkInterfacesOutput::builder()
            .network_interfaces(
                NetworkInterface::builder()
                    .network_interface_id("eni-1")
                    .vpc_id("vpc-1")
                    .subnet_id("subnet-1")
                    .private_ip_address("10.0.0.5")
                    .groups(GroupIdentifier::builder().group_id("sg-1").build())
                    .build(),
            )
            .build()
    });
    let rules = [
        sg_rule,
        empty_network_acls_rule(),
        empty_route_tables_rule(),
        eni_rule,
        empty_vpc_peering_connections_rule(),
    ];
    let rule_refs: Vec<&Rule> = rules.iter().collect();
    let client = mock_ec2_client(&rule_refs);
    let writer = InMemoryGraphWriter::default();

    // Act
    let result = run_full_ingest_with_client(&client, ACCOUNT_ID, &writer).await;

    // Assert
    let report = match result {
        Ok(report) => report,
        Err(err) => panic!("expected Ok: {err:?}"),
    };
    assert_eq!(
        report.counts[&aws_net_hound_core::ingest::pipeline::ResourceKind::Eni],
        1
    );
    assert_eq!(
        report.counts[&aws_net_hound_core::ingest::pipeline::ResourceKind::SecurityGroup],
        1
    );
    assert_eq!(writer.node_count(), 4); // eni + sg + synthesized vpc + subnet
}

#[tokio::test]
async fn run_full_ingest_cross_account_sg_reference_increments_unresolved_count() {
    // Arrange
    use aws_sdk_ec2::types::{IpPermission, UserIdGroupPair};

    let sg_rule = mock!(Client::describe_security_groups).then_output(|| {
        DescribeSecurityGroupsOutput::builder()
            .security_groups(
                SecurityGroup::builder()
                    .group_id("sg-1")
                    .vpc_id("vpc-1")
                    .group_name("sg")
                    .ip_permissions(
                        IpPermission::builder()
                            .ip_protocol("-1")
                            .user_id_group_pairs(
                                UserIdGroupPair::builder()
                                    .group_id("sg-2")
                                    .user_id("999999999999")
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .build()
    });
    let rules = [
        sg_rule,
        empty_network_acls_rule(),
        empty_route_tables_rule(),
        empty_network_interfaces_rule(),
        empty_vpc_peering_connections_rule(),
    ];
    let rule_refs: Vec<&Rule> = rules.iter().collect();
    let client = mock_ec2_client(&rule_refs);
    let writer = InMemoryGraphWriter::default();

    // Act
    let result = run_full_ingest_with_client(&client, ACCOUNT_ID, &writer).await;

    // Assert
    let report = match result {
        Ok(report) => report,
        Err(err) => panic!("expected Ok: {err:?}"),
    };
    assert_eq!(report.unresolved_references, 1);
}

#[tokio::test]
async fn run_full_ingest_single_unmappable_resource_records_warning_and_completes() {
    // Arrange: one ENI missing `subnet_id` (required field) alongside one
    // valid security group — the malformed ENI must not abort the run.
    let sg_rule = mock!(Client::describe_security_groups).then_output(|| {
        DescribeSecurityGroupsOutput::builder()
            .security_groups(
                SecurityGroup::builder()
                    .group_id("sg-1")
                    .vpc_id("vpc-1")
                    .group_name("sg")
                    .build(),
            )
            .build()
    });
    let eni_rule = mock!(Client::describe_network_interfaces).then_output(|| {
        DescribeNetworkInterfacesOutput::builder()
            .network_interfaces(
                NetworkInterface::builder()
                    .network_interface_id("eni-bad")
                    .vpc_id("vpc-1")
                    .private_ip_address("10.0.0.5")
                    .build(),
            )
            .build()
    });
    let rules = [
        sg_rule,
        empty_network_acls_rule(),
        empty_route_tables_rule(),
        eni_rule,
        empty_vpc_peering_connections_rule(),
    ];
    let rule_refs: Vec<&Rule> = rules.iter().collect();
    let client = mock_ec2_client(&rule_refs);
    let writer = InMemoryGraphWriter::default();

    // Act
    let result = run_full_ingest_with_client(&client, ACCOUNT_ID, &writer).await;

    // Assert
    let report = match result {
        Ok(report) => report,
        Err(err) => panic!("expected the run to complete despite one bad resource: {err:?}"),
    };
    assert_eq!(report.non_fatal.len(), 1);
    assert_eq!(report.non_fatal[0].resource_id, "eni-bad");
    assert_eq!(report.non_fatal[0].field, "subnet_id");
    assert_eq!(
        report.counts[&aws_net_hound_core::ingest::pipeline::ResourceKind::SecurityGroup],
        1
    );
}

#[tokio::test]
async fn run_full_ingest_graph_write_failure_returns_err_not_partial_report() {
    // Arrange
    let rules = [
        empty_security_groups_rule(),
        empty_network_acls_rule(),
        empty_route_tables_rule(),
        empty_network_interfaces_rule(),
        empty_vpc_peering_connections_rule(),
    ];
    let rule_refs: Vec<&Rule> = rules.iter().collect();
    let client = mock_ec2_client(&rule_refs);
    let writer = InMemoryGraphWriter::failing();

    // Act
    let result = run_full_ingest_with_client(&client, ACCOUNT_ID, &writer).await;

    // Assert
    assert!(matches!(
        result,
        Err(aws_net_hound_core::error::IngestError::Write { .. })
    ));
}
