//! Docker-gated integration tests for `run` orchestration, matching CI job
//! `integration-tests` (`cargo test --workspace -- --ignored`).
//!
//! Brings up the same `docker compose` Neo4j stack `preflight_integration.rs`
//! uses (so `run`'s own preflight stage passes against it), and mocks EC2
//! via `aws-smithy-mocks` — `run_with_ec2_client` is the seam that makes
//! this possible without a real AWS account or credentials in CI.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use audit_local::config::{Config, ValidatedConfig};
use audit_local::run::run_with_ec2_client;
use audit_local::Outcome;
use aws_sdk_ec2::operation::describe_network_acls::DescribeNetworkAclsOutput;
use aws_sdk_ec2::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput;
use aws_sdk_ec2::operation::describe_route_tables::DescribeRouteTablesOutput;
use aws_sdk_ec2::operation::describe_security_groups::DescribeSecurityGroupsOutput;
use aws_sdk_ec2::operation::describe_vpc_peering_connections::DescribeVpcPeeringConnectionsOutput;
use aws_sdk_ec2::Client;
use aws_smithy_mocks::{mock, Rule};
use neo4rs::{query, ConfigBuilder, Graph};

const COMPOSE_DIR: &str = env!("CARGO_MANIFEST_DIR");
const ACCOUNT_ID: &str = "123456789012";

fn test_password() -> String {
    std::env::var("NEO4J_PASSWORD").unwrap_or_else(|_| {
        panic!(
            "run this test with NEO4J_PASSWORD set, e.g.:\n  \
             NEO4J_PASSWORD=test cargo test -p audit-local --test run_integration -- --ignored"
        )
    })
}

fn compose_down(password: &str) {
    let _ = Command::new("docker")
        .args(["compose", "down", "-v"])
        .current_dir(COMPOSE_DIR)
        .env("NEO4J_PASSWORD", password)
        .output();
}

struct ComposeGuard {
    password: String,
}

impl Drop for ComposeGuard {
    fn drop(&mut self) {
        compose_down(&self.password);
    }
}

fn compose_up(password: &str) {
    let up = Command::new("docker")
        .args(["compose", "up", "-d"])
        .current_dir(COMPOSE_DIR)
        .env("NEO4J_PASSWORD", password)
        .output()
        .expect("failed to spawn docker compose up");
    assert!(
        up.status.success(),
        "docker compose up failed: {}",
        String::from_utf8_lossy(&up.stderr)
    );
}

fn validated_config() -> ValidatedConfig {
    let yaml = r#"
region: us-east-1
profile: default
boundary:
  vpc_ids:
    - vpc-1
output_path: ./audit-report.json
neo4j:
  uri: bolt://127.0.0.1:7687
  user: neo4j
"#;
    let config = Config::parse(yaml).expect("test yaml parses");
    config.validate().expect("test yaml validates")
}

fn empty_ec2_client() -> Client {
    let sg_rule = mock!(Client::describe_security_groups)
        .then_output(|| DescribeSecurityGroupsOutput::builder().build());
    let nacl_rule = mock!(Client::describe_network_acls)
        .then_output(|| DescribeNetworkAclsOutput::builder().build());
    let route_table_rule = mock!(Client::describe_route_tables)
        .then_output(|| DescribeRouteTablesOutput::builder().build());
    let eni_rule = mock!(Client::describe_network_interfaces)
        .then_output(|| DescribeNetworkInterfacesOutput::builder().build());
    let peering_rule = mock!(Client::describe_vpc_peering_connections)
        .then_output(|| DescribeVpcPeeringConnectionsOutput::builder().build());
    let rules: Vec<&Rule> = vec![
        &sg_rule,
        &nacl_rule,
        &route_table_rule,
        &eni_rule,
        &peering_rule,
    ];
    aws_smithy_mocks::mock_client!(aws_sdk_ec2, aws_smithy_mocks::RuleMode::MatchAny, rules)
}

async fn graph_counts(graph: &Graph) -> (i64, i64) {
    let mut node_stream = graph
        .execute(query("MATCH (n) RETURN count(n) AS count"))
        .await
        .expect("node count query runs");
    let node_count: i64 = node_stream
        .next()
        .await
        .expect("node count row present")
        .expect("node count row present")
        .get("count")
        .expect("count field present");

    let mut edge_stream = graph
        .execute(query("MATCH ()-[r]->() RETURN count(r) AS count"))
        .await
        .expect("edge count query runs");
    let edge_count: i64 = edge_stream
        .next()
        .await
        .expect("edge count row present")
        .expect("edge count row present")
        .get("count")
        .expect("count field present");

    (node_count, edge_count)
}

#[tokio::test]
#[ignore]
async fn run_against_empty_graph_applies_migrations_then_evaluates() {
    let password = test_password();
    let _guard = ComposeGuard {
        password: password.clone(),
    };
    compose_down(&password);
    compose_up(&password);

    let client = empty_ec2_client();
    let outcome = run_with_ec2_client(validated_config(), &client, ACCOUNT_ID)
        .await
        .expect("run succeeds against an empty account");

    assert_eq!(outcome, Outcome::Clean);
}

#[tokio::test]
#[ignore]
async fn run_twice_does_not_duplicate_graph_nodes() {
    let password = test_password();
    let _guard = ComposeGuard {
        password: password.clone(),
    };
    compose_down(&password);
    compose_up(&password);

    let client = empty_ec2_client();
    run_with_ec2_client(validated_config(), &client, ACCOUNT_ID)
        .await
        .expect("first run succeeds");

    let neo4j_config = ConfigBuilder::new()
        .uri("bolt://127.0.0.1:7687")
        .user("neo4j")
        .password(&password)
        .build()
        .expect("valid neo4j config");
    let graph = Graph::connect(neo4j_config)
        .await
        .expect("graph connects for count query");
    let before = graph_counts(&graph).await;

    run_with_ec2_client(validated_config(), &client, ACCOUNT_ID)
        .await
        .expect("second run succeeds");
    let after = graph_counts(&graph).await;

    assert_eq!(before, after);
}
