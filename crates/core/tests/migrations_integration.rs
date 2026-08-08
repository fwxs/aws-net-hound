//! Docker-gated integration tests for the migration runner. Run with:
//!
//! ```bash
//! cargo test -p core -- --ignored
//! ```

// Assertions here compare live Neo4j state; unwrap/expect on container and
// driver setup keep the arrange step readable and fail loudly if the fixture
// itself is broken, which is not what any single test is asserting on.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;

use aws_net_hound_core::migrations;
use neo4rs::{query, ConfigBuilder, Graph};
use pretty_assertions::assert_eq;
use testcontainers::{core::WaitFor, runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt};

const NEO4J_IMAGE: &str = "neo4j";
const NEO4J_TAG: &str = "5";
const NEO4J_USER: &str = "neo4j";

// Per-run credential: an env var override for local debugging, otherwise a
// value derived from the process id and current time. Never a literal —
// literals in integration tests are a classic place for a real credential
// to get copy-pasted in later and leak into git history.
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

async fn constraint_names(graph: &Graph) -> HashSet<String> {
    let mut stream = graph
        .execute(query("SHOW CONSTRAINTS YIELD name RETURN name"))
        .await
        .expect("SHOW CONSTRAINTS succeeds");

    let mut names = HashSet::new();
    while let Some(row) = stream.next().await.expect("row streams") {
        names.insert(row.get::<String>("name").expect("name is a string"));
    }
    names
}

async fn index_names(graph: &Graph) -> HashSet<String> {
    let mut stream = graph
        .execute(query("SHOW INDEXES YIELD name RETURN name"))
        .await
        .expect("SHOW INDEXES succeeds");

    let mut names = HashSet::new();
    while let Some(row) = stream.next().await.expect("row streams") {
        names.insert(row.get::<String>("name").expect("name is a string"));
    }
    names
}

async fn schema_migration_versions(graph: &Graph) -> Vec<i64> {
    let mut stream = graph
        .execute(query(
            "MATCH (n:SchemaMigration) RETURN n.version AS version ORDER BY n.version",
        ))
        .await
        .expect("SchemaMigration query succeeds");

    let mut versions = Vec::new();
    while let Some(row) = stream.next().await.expect("row streams") {
        versions.push(row.get::<i64>("version").expect("version is an int"));
    }
    versions
}

#[tokio::test]
#[ignore]
async fn run_migrations_on_clean_database_applies_all_versions() {
    // Arrange
    let (_container, graph) = start_neo4j().await;

    // Act
    let summary = migrations::run(&graph).await.expect("migrations apply");

    // Assert
    assert_eq!(summary.applied, vec![1, 2]);
    assert!(summary.skipped.is_empty());

    let expected_constraints: HashSet<String> = [
        "schema_migration_version_unique",
        "eni_id_unique",
        "security_group_id_unique",
        "network_acl_id_unique",
        "subnet_id_unique",
        "vpc_id_unique",
        "route_table_id_unique",
        "regulated_boundary_id_unique",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(constraint_names(&graph).await, expected_constraints);

    let expected_indexes: HashSet<String> = [
        "eni_account_id_idx",
        "security_group_account_id_idx",
        "network_acl_account_id_idx",
        "subnet_account_id_idx",
        "vpc_account_id_idx",
        "route_table_account_id_idx",
        "regulated_boundary_account_id_idx",
        "eni_vpc_id_idx",
        "security_group_vpc_id_idx",
        "network_acl_vpc_id_idx",
        "subnet_vpc_id_idx",
        "route_table_vpc_id_idx",
        "allows_egress_resolved_idx",
        "allows_ingress_resolved_idx",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    // Uniqueness constraints back their own index, so those show up in
    // SHOW INDEXES too — only assert the standalone ones are a subset.
    let actual_indexes = index_names(&graph).await;
    for expected in &expected_indexes {
        assert!(
            actual_indexes.contains(expected),
            "missing index: {expected}"
        );
    }
}

#[tokio::test]
#[ignore]
async fn run_migrations_twice_is_idempotent() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    migrations::run(&graph).await.expect("first run applies");
    let constraints_after_first_run = constraint_names(&graph).await;
    let indexes_after_first_run = index_names(&graph).await;
    let schema_versions_after_first_run = schema_migration_versions(&graph).await;

    // Act
    let summary = migrations::run(&graph).await.expect("second run succeeds");

    // Assert
    assert!(summary.applied.is_empty());
    assert_eq!(summary.skipped, vec![1, 2]);
    assert_eq!(constraint_names(&graph).await, constraints_after_first_run);
    assert_eq!(index_names(&graph).await, indexes_after_first_run);
    assert_eq!(
        schema_migration_versions(&graph).await,
        schema_versions_after_first_run
    );
}

#[tokio::test]
#[ignore]
async fn run_migrations_records_version_only_after_success() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    let failing_source = "CREATE CONSTRAINT bogus_ok_unique IF NOT EXISTS FOR (n:Bogus) REQUIRE n.id IS UNIQUE;\nTHIS IS NOT VALID CYPHER;";

    // Act
    let result = migrations::apply_version(&graph, 999, failing_source).await;

    // Assert
    assert!(result.is_err());
    assert!(!schema_migration_versions(&graph).await.contains(&999));
}
