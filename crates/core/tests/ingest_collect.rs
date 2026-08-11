//! Integration tests for [`aws_net_hound_core::ingest::collect`].
//!
//! Uses `aws-smithy-mocks` to intercept requests below the HTTP layer, so
//! these tests need no AWS account, no network, and no Docker — they run
//! in the plain `cargo test --workspace` job.

use std::time::Duration;

use aws_net_hound_core::error::IngestError;
use aws_net_hound_core::ingest::collect::{
    collect_network_acls, collect_network_interfaces, collect_route_tables,
    collect_security_groups, collect_vpc_peering_connections,
};
use aws_sdk_ec2::config::retry::RetryConfig;
use aws_sdk_ec2::error::ErrorMetadata;
use aws_sdk_ec2::operation::describe_network_acls::DescribeNetworkAclsError;
use aws_sdk_ec2::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput;
use aws_sdk_ec2::operation::describe_route_tables::{
    DescribeRouteTablesError, DescribeRouteTablesOutput,
};
use aws_sdk_ec2::operation::describe_security_groups::DescribeSecurityGroupsOutput;
use aws_sdk_ec2::operation::describe_vpc_peering_connections::DescribeVpcPeeringConnectionsOutput;
use aws_sdk_ec2::types::{NetworkInterface, RouteTable, SecurityGroup, VpcPeeringConnection};
use aws_sdk_ec2::Client;
use aws_smithy_mocks::{mock, mock_client, Rule, RuleMode};
use pretty_assertions::assert_eq;

/// A retry config with negligible backoff, so tests that trigger a retry
/// don't sleep for real backoff durations.
fn fast_retry_config() -> RetryConfig {
    RetryConfig::standard()
        .with_max_attempts(3)
        .with_initial_backoff(Duration::from_millis(1))
        .with_max_backoff(Duration::from_millis(5))
}

/// Builds a mock EC2 client that serves `rules` in order and applies
/// [`fast_retry_config`] so retry-triggering tests stay fast.
fn mock_ec2_client(rules: &[&Rule]) -> Client {
    mock_client!(aws_sdk_ec2, RuleMode::Sequential, rules, |conf| conf
        .retry_config(fast_retry_config()))
}

#[tokio::test]
async fn collect_security_groups_multi_page_response_returns_all_items() {
    // Arrange
    let rule = mock!(Client::describe_security_groups)
        .sequence()
        .output(|| {
            DescribeSecurityGroupsOutput::builder()
                .security_groups(SecurityGroup::builder().group_id("sg-1").build())
                .next_token("page-2")
                .build()
        })
        .output(|| {
            DescribeSecurityGroupsOutput::builder()
                .security_groups(SecurityGroup::builder().group_id("sg-2").build())
                .next_token("page-3")
                .build()
        })
        .output(|| {
            DescribeSecurityGroupsOutput::builder()
                .security_groups(SecurityGroup::builder().group_id("sg-3").build())
                .build()
        })
        .build();
    let client = mock_ec2_client(&[&rule]);

    // Act
    let result = collect_security_groups(&client).await;

    // Assert
    let security_groups = match result {
        Ok(security_groups) => security_groups,
        Err(err) => panic!("expected all three pages to collect, got {err:?}"),
    };
    let group_ids: Vec<Option<&str>> = security_groups
        .iter()
        .map(|group| group.group_id())
        .collect();
    assert_eq!(group_ids, vec![Some("sg-1"), Some("sg-2"), Some("sg-3")]);
}

#[tokio::test]
async fn collect_security_groups_single_empty_page_returns_empty_vec() {
    // Arrange
    let rule = mock!(Client::describe_security_groups)
        .then_output(|| DescribeSecurityGroupsOutput::builder().build());
    let client = mock_ec2_client(&[&rule]);

    // Act
    let result = collect_security_groups(&client).await;

    // Assert
    let security_groups = match result {
        Ok(security_groups) => security_groups,
        Err(err) => panic!("expected an empty page to collect as an empty Vec, got {err:?}"),
    };
    assert_eq!(security_groups, Vec::<SecurityGroup>::new());
}

#[tokio::test]
async fn collect_network_interfaces_multi_page_response_returns_all_items() {
    // Arrange
    let rule = mock!(Client::describe_network_interfaces)
        .sequence()
        .output(|| {
            DescribeNetworkInterfacesOutput::builder()
                .network_interfaces(
                    NetworkInterface::builder()
                        .network_interface_id("eni-1")
                        .build(),
                )
                .next_token("page-2")
                .build()
        })
        .output(|| {
            DescribeNetworkInterfacesOutput::builder()
                .network_interfaces(
                    NetworkInterface::builder()
                        .network_interface_id("eni-2")
                        .build(),
                )
                .build()
        })
        .build();
    let client = mock_ec2_client(&[&rule]);

    // Act
    let result = collect_network_interfaces(&client).await;

    // Assert
    let network_interfaces = match result {
        Ok(network_interfaces) => network_interfaces,
        Err(err) => panic!("expected both pages to collect, got {err:?}"),
    };
    let interface_ids: Vec<Option<&str>> = network_interfaces
        .iter()
        .map(|eni| eni.network_interface_id())
        .collect();
    assert_eq!(interface_ids, vec![Some("eni-1"), Some("eni-2")]);
}

#[tokio::test]
async fn collect_route_tables_throttled_once_then_success_returns_items() {
    // Arrange: the first attempt is throttled, proving the client's retry
    // policy (configured in build_ec2_client, M1-T1) is exercised by the
    // collector rather than surfacing the throttle as an immediate error.
    let rule = mock!(Client::describe_route_tables)
        .sequence()
        .error(|| {
            DescribeRouteTablesError::generic(
                ErrorMetadata::builder()
                    .code("RequestLimitExceeded")
                    .message("Request limit exceeded.")
                    .build(),
            )
        })
        .output(|| {
            DescribeRouteTablesOutput::builder()
                .route_tables(RouteTable::builder().route_table_id("rtb-1").build())
                .build()
        })
        .build();
    let client = mock_ec2_client(&[&rule]);

    // Act
    let result = collect_route_tables(&client).await;

    // Assert
    let route_tables = match result {
        Ok(route_tables) => route_tables,
        Err(err) => panic!("expected the retried request to succeed, got {err:?}"),
    };
    let route_table_ids: Vec<Option<&str>> = route_tables
        .iter()
        .map(|route_table| route_table.route_table_id())
        .collect();
    assert_eq!(route_table_ids, vec![Some("rtb-1")]);
    assert_eq!(rule.num_calls(), 2);
}

#[tokio::test]
async fn collect_network_acls_persistent_error_returns_ingest_error() {
    // Arrange: a non-retryable error code, so the client fails on its
    // first attempt without waiting on retry backoff.
    let rule = mock!(Client::describe_network_acls).then_error(|| {
        DescribeNetworkAclsError::generic(
            ErrorMetadata::builder()
                .code("AuthFailure")
                .message("AWS was not able to validate the provided access credentials.")
                .build(),
        )
    });
    let client = mock_ec2_client(&[&rule]);

    // Act
    let result = collect_network_acls(&client).await;

    // Assert
    match result {
        Err(IngestError::Describe { operation, .. }) => {
            assert_eq!(operation, "DescribeNetworkAcls");
        }
        other => panic!("expected IngestError::Describe naming the operation, got {other:?}"),
    }
}

#[tokio::test]
async fn collect_vpc_peering_connections_multi_page_response_returns_all_items() {
    // Arrange
    let rule = mock!(Client::describe_vpc_peering_connections)
        .sequence()
        .output(|| {
            DescribeVpcPeeringConnectionsOutput::builder()
                .vpc_peering_connections(
                    VpcPeeringConnection::builder()
                        .vpc_peering_connection_id("pcx-1")
                        .build(),
                )
                .next_token("page-2")
                .build()
        })
        .output(|| {
            DescribeVpcPeeringConnectionsOutput::builder()
                .vpc_peering_connections(
                    VpcPeeringConnection::builder()
                        .vpc_peering_connection_id("pcx-2")
                        .build(),
                )
                .build()
        })
        .build();
    let client = mock_ec2_client(&[&rule]);

    // Act
    let result = collect_vpc_peering_connections(&client).await;

    // Assert
    let vpc_peering_connections = match result {
        Ok(vpc_peering_connections) => vpc_peering_connections,
        Err(err) => panic!("expected both pages to collect, got {err:?}"),
    };
    let peering_connection_ids: Vec<Option<&str>> = vpc_peering_connections
        .iter()
        .map(|peering_connection| peering_connection.vpc_peering_connection_id())
        .collect();
    assert_eq!(peering_connection_ids, vec![Some("pcx-1"), Some("pcx-2")]);
}
