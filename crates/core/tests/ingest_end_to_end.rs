//! Docker-gated end-to-end test closing the loop on the full Milestone 1
//! pipeline: mocked AWS responses through `run_full_ingest_with_client`,
//! written to a real Neo4j via `Neo4jGraphWriter`. Run with:
//!
//! ```bash
//! cargo test -p core -- --ignored
//! ```

// Container/driver setup unwraps keep the arrange step readable and fail
// loudly if the fixture itself is broken — not what this test asserts on.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use aws_net_hound_core::graph::neo4j::Neo4jGraphWriter;
use aws_net_hound_core::ingest::pipeline::run_full_ingest_with_client;
use aws_net_hound_core::migrations;
use aws_sdk_ec2::config::retry::RetryConfig;
use aws_sdk_ec2::operation::describe_network_acls::DescribeNetworkAclsOutput;
use aws_sdk_ec2::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput;
use aws_sdk_ec2::operation::describe_route_tables::DescribeRouteTablesOutput;
use aws_sdk_ec2::operation::describe_security_groups::DescribeSecurityGroupsOutput;
use aws_sdk_ec2::operation::describe_vpc_peering_connections::DescribeVpcPeeringConnectionsOutput;
use aws_sdk_ec2::types::{GroupIdentifier, NetworkInterface, SecurityGroup};
use aws_sdk_ec2::Client;
use aws_smithy_mocks::{mock, mock_client, Rule, RuleMode};
use neo4rs::{ConfigBuilder, Graph};
use pretty_assertions::assert_eq;
use std::time::Duration;
use testcontainers::{core::WaitFor, runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt};

const NEO4J_IMAGE: &str = "neo4j";
const NEO4J_TAG: &str = "5";
const NEO4J_USER: &str = "neo4j";
const ACCOUNT_ID: &str = "123456789012";

fn test_password() -> String {
    if let Ok(password) = std::env::var("NEO4J_TEST_PASSWORD") {
        return password;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after unix epoch")
        .as_nanos();
    format!("itp-{}-{nanos}", std::process::id())
}

async fn start_neo4j() -> (ContainerAsync<GenericImage>, Graph) {
    let password = test_password();
    let container = GenericImage::new(NEO4J_IMAGE, NEO4J_TAG)
        .with_wait_for(WaitFor::message_on_stdout("Bolt enabled on"))
        .with_env_var("NEO4J_AUTH", format!("{NEO4J_USER}/{password}"))
        .start()
        .await
        .expect("neo4j container starts");

    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(7687)
        .await
        .expect("bolt port mapping");

    let config = ConfigBuilder::default()
        .uri(format!("bolt://{host}:{port}"))
        .user(NEO4J_USER)
        .password(&password)
        .build()
        .expect("valid neo4j config");

    let graph = Graph::connect(config).await.expect("graph connects");
    (container, graph)
}

fn fast_retry_config() -> RetryConfig {
    RetryConfig::standard()
        .with_max_attempts(3)
        .with_initial_backoff(Duration::from_millis(1))
        .with_max_backoff(Duration::from_millis(5))
}

fn mock_ec2_client(rules: &[&Rule]) -> Client {
    mock_client!(aws_sdk_ec2, RuleMode::MatchAny, rules, |conf| conf
        .retry_config(fast_retry_config()))
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn run_full_ingest_against_neo4j_twice_produces_identical_graph_counts() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    migrations::run(&graph)
        .await
        .expect("schema migrations apply");
    let writer = Neo4jGraphWriter::new(graph.clone());

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
    let nacl_rule = mock!(Client::describe_network_acls)
        .then_output(|| DescribeNetworkAclsOutput::builder().build());
    let route_table_rule = mock!(Client::describe_route_tables)
        .then_output(|| DescribeRouteTablesOutput::builder().build());
    let peering_rule = mock!(Client::describe_vpc_peering_connections)
        .then_output(|| DescribeVpcPeeringConnectionsOutput::builder().build());
    let rules: Vec<&Rule> = vec![
        &sg_rule,
        &nacl_rule,
        &route_table_rule,
        &eni_rule,
        &peering_rule,
    ];
    let client = mock_ec2_client(&rules);

    // Act
    let first = run_full_ingest_with_client(&client, ACCOUNT_ID, &writer)
        .await
        .expect("first ingest succeeds");
    let second = run_full_ingest_with_client(&client, ACCOUNT_ID, &writer)
        .await
        .expect("second ingest succeeds");

    // Assert: re-ingesting the same account must MERGE in place, not
    // duplicate — identical counts across both runs closes the loop on
    // idempotency for the whole pipeline, not just one writer method.
    assert_eq!(first.counts, second.counts);
    assert_eq!(first.unresolved_references, second.unresolved_references);
}
