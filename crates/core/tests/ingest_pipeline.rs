//! Integration tests for [`aws_net_hound_core::ingest::pipeline::run_full_ingest`].
//!
//! Drives `run_full_ingest_with_client` (the client/account-id-injectable
//! seam behind the public `run_full_ingest`) with `aws-smithy-mocks` for the
//! AWS boundary and an in-memory `GraphWriter`, so the whole pipeline runs
//! with no AWS account, no network, and no Docker — plain
//! `cargo test --workspace`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Mutex;

use aws_net_hound_core::error::GraphWriteError;
use aws_net_hound_core::ingest::pipeline::{run_full_ingest_with_client, IngestWarningReason};
use aws_net_hound_core::ports::{
    BoxFuture, EniRecord, GraphWriter, HasSgEdge, InSubnetEdge, NaclRuleBatch, NetworkAclRecord,
    ProtectedByEdge, RegulatedBoundaryRecord, RouteTableRecord, RoutesToEdge, SecurityGroupRecord,
    SgRuleBatch, SubnetRecord, UsesRouteTableEdge, VpcRecord,
};
use aws_sdk_ec2::config::retry::RetryConfig;
use aws_sdk_ec2::operation::describe_network_acls::DescribeNetworkAclsOutput;
use aws_sdk_ec2::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput;
use aws_sdk_ec2::operation::describe_route_tables::DescribeRouteTablesOutput;
use aws_sdk_ec2::operation::describe_security_groups::DescribeSecurityGroupsOutput;
use aws_sdk_ec2::operation::describe_vpc_peering_connections::DescribeVpcPeeringConnectionsOutput;
use aws_sdk_ec2::types::{GroupIdentifier, NetworkInterface, SecurityGroup};
use aws_sdk_ec2::Client;
use aws_smithy_mocks::{mock, mock_client, Rule, RuleMode};
use pretty_assertions::assert_eq;
use std::time::Duration;

const ACCOUNT_ID: &str = "123456789012";

fn fast_retry_config() -> RetryConfig {
    RetryConfig::standard()
        .with_max_attempts(3)
        .with_initial_backoff(Duration::from_millis(1))
        .with_max_backoff(Duration::from_millis(5))
}

/// Builds a mock EC2 client serving `rules`, defaulting every unmentioned
/// `Describe*` call to a single empty page so a test only needs to stub the
/// operations it cares about.
fn mock_ec2_client(rules: &[&Rule]) -> Client {
    mock_client!(aws_sdk_ec2, RuleMode::MatchAny, rules, |conf| conf
        .retry_config(fast_retry_config()))
}

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

/// Minimal `GraphWriter` backed by `HashMap`s guarded by `std::sync::Mutex`,
/// mirroring `tests/contracts.rs`'s `InMemoryGraphWriter` — trimmed to what
/// this file's assertions need plus a `fail_writes` switch for the
/// write-failure test.
#[derive(Default)]
struct InMemoryGraphWriter {
    fail_writes: bool,
    enis: Mutex<HashMap<String, EniRecord>>,
    security_groups: Mutex<HashMap<String, SecurityGroupRecord>>,
    network_acls: Mutex<HashMap<String, NetworkAclRecord>>,
    subnets: Mutex<HashMap<String, SubnetRecord>>,
    vpcs: Mutex<HashMap<String, VpcRecord>>,
    route_tables: Mutex<HashMap<String, RouteTableRecord>>,
}

impl InMemoryGraphWriter {
    fn failing() -> Self {
        Self {
            fail_writes: true,
            ..Self::default()
        }
    }

    fn node_count(&self) -> usize {
        self.enis.lock().unwrap().len()
            + self.security_groups.lock().unwrap().len()
            + self.network_acls.lock().unwrap().len()
            + self.subnets.lock().unwrap().len()
            + self.vpcs.lock().unwrap().len()
            + self.route_tables.lock().unwrap().len()
    }
}

fn upsert<K, V>(store: &Mutex<HashMap<K, V>>, key_fn: impl Fn(&V) -> K, records: &[V])
where
    K: Eq + std::hash::Hash,
    V: Clone,
{
    let mut guard = store.lock().unwrap();
    for record in records {
        guard.insert(key_fn(record), record.clone());
    }
}

fn write_failed() -> GraphWriteError {
    GraphWriteError::Write {
        source: "simulated write failure".into(),
    }
}

impl GraphWriter for InMemoryGraphWriter {
    fn upsert_enis(&self, enis: &[EniRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(&self.enis, |record| record.id.clone(), enis);
        Box::pin(async { Ok(()) })
    }

    fn upsert_security_groups(
        &self,
        security_groups: &[SecurityGroupRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(
            &self.security_groups,
            |record| record.id.clone(),
            security_groups,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_network_acls(
        &self,
        network_acls: &[NetworkAclRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.network_acls, |record| record.id.clone(), network_acls);
        Box::pin(async { Ok(()) })
    }

    fn upsert_subnets(
        &self,
        subnets: &[SubnetRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.subnets, |record| record.id.clone(), subnets);
        Box::pin(async { Ok(()) })
    }

    fn upsert_vpcs(&self, vpcs: &[VpcRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.vpcs, |record| record.id.clone(), vpcs);
        Box::pin(async { Ok(()) })
    }

    fn upsert_route_tables(
        &self,
        route_tables: &[RouteTableRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        upsert(&self.route_tables, |record| record.id.clone(), route_tables);
        Box::pin(async { Ok(()) })
    }

    fn upsert_regulated_boundaries(
        &self,
        _boundaries: &[RegulatedBoundaryRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_has_sg_edges(
        &self,
        _edges: &[HasSgEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_in_subnet_edges(
        &self,
        _edges: &[InSubnetEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_protected_by_edges(
        &self,
        _edges: &[ProtectedByEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_uses_route_table_edges(
        &self,
        _edges: &[UsesRouteTableEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_routes_to_edges(
        &self,
        _edges: &[RoutesToEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_allows_egress_rules(
        &self,
        _batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_allows_ingress_rules(
        &self,
        _batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_has_rules(
        &self,
        _batches: &[NaclRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        Box::pin(async { Ok(()) })
    }
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
    assert!(matches!(
        report.non_fatal[0].reason,
        IngestWarningReason::InvalidField {
            field: "subnet_id",
            ..
        }
    ));
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

#[tokio::test]
async fn run_full_ingest_report_serializes_to_json_with_all_fields() {
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
    let report = run_full_ingest_with_client(&client, ACCOUNT_ID, &writer)
        .await
        .unwrap_or_else(|error| panic!("expected Ok: {error}"));

    // Act
    let json = serde_json::to_string(&report).expect("report must serialize to JSON");

    // Assert
    assert!(json.contains("\"counts\""));
    assert!(json.contains("\"unresolved_references\""));
    assert!(json.contains("\"duration\""));
    assert!(json.contains("\"non_fatal\""));
}
