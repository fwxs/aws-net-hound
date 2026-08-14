//! Docker-gated integration tests for [`Neo4jGraphWriter`]. Run with:
//!
//! ```bash
//! cargo test -p core -- --ignored
//! ```

// Assertions here compare live Neo4j state; unwrap/expect on container and
// driver setup keep the arrange step readable and fail loudly if the fixture
// itself is broken, which is not what any single test is asserting on.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use aws_net_hound_core::domain::rule::{
    Action, Direction, NaclRule, PortRange, RuleTarget, SgRule,
};
use aws_net_hound_core::graph::neo4j::Neo4jGraphWriter;
use aws_net_hound_core::migrations;
use aws_net_hound_core::ports::{
    EniRecord, GraphWriter, HasSgEdge, NaclRuleBatch, NetworkAclRecord, RouteTableRecord,
    RoutesToEdge, SecurityGroupRecord, SgRuleBatch, SubnetRecord, VpcRecord,
};
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

async fn node_count(graph: &Graph, label: &str) -> i64 {
    let mut stream = graph
        .execute(query(&format!("MATCH (n:{label}) RETURN count(n) AS c")))
        .await
        .expect("node count query succeeds");
    let row = stream
        .next()
        .await
        .expect("row streams")
        .expect("count row present");
    row.get::<i64>("c").expect("count is an int")
}

async fn relationship_count(graph: &Graph, rel_type: &str) -> i64 {
    let mut stream = graph
        .execute(query(&format!(
            "MATCH ()-[r:{rel_type}]->() RETURN count(r) AS c"
        )))
        .await
        .expect("relationship count query succeeds");
    let row = stream
        .next()
        .await
        .expect("row streams")
        .expect("count row present");
    row.get::<i64>("c").expect("count is an int")
}

fn eni(id: &str, vpc_id: &str, subnet_id: &str) -> EniRecord {
    EniRecord {
        id: id.to_string(),
        account_id: "123456789012".to_string(),
        vpc_id: vpc_id.to_string(),
        subnet_id: subnet_id.to_string(),
        private_ip: "10.0.0.5".to_string(),
        description: None,
    }
}

fn security_group(id: &str, vpc_id: &str, name: &str) -> SecurityGroupRecord {
    SecurityGroupRecord {
        id: id.to_string(),
        account_id: "123456789012".to_string(),
        vpc_id: vpc_id.to_string(),
        name: name.to_string(),
        description: None,
    }
}

fn subnet(id: &str, vpc_id: &str) -> SubnetRecord {
    SubnetRecord {
        id: id.to_string(),
        account_id: "123456789012".to_string(),
        vpc_id: vpc_id.to_string(),
        cidr_block: String::new(),
        availability_zone: String::new(),
    }
}

fn vpc(id: &str) -> VpcRecord {
    VpcRecord {
        id: id.to_string(),
        account_id: "123456789012".to_string(),
        cidr_block: String::new(),
    }
}

fn network_acl(id: &str, vpc_id: &str) -> NetworkAclRecord {
    NetworkAclRecord {
        id: id.to_string(),
        account_id: "123456789012".to_string(),
        vpc_id: vpc_id.to_string(),
        is_default: false,
    }
}

fn route_table(id: &str, vpc_id: &str) -> RouteTableRecord {
    RouteTableRecord {
        id: id.to_string(),
        account_id: "123456789012".to_string(),
        vpc_id: vpc_id.to_string(),
        is_main: false,
    }
}

async fn seed_migrations(graph: &Graph) {
    migrations::run(graph).await.expect("migrations apply");
}

#[tokio::test]
#[ignore]
async fn write_batch_on_clean_database_creates_expected_node_and_edge_counts() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());

    // Act
    writer
        .upsert_vpcs(&[vpc("vpc-1")])
        .await
        .expect("vpcs upsert");
    writer
        .upsert_subnets(&[subnet("subnet-1", "vpc-1")])
        .await
        .expect("subnets upsert");
    writer
        .upsert_security_groups(&[security_group("sg-1", "vpc-1", "web")])
        .await
        .expect("security groups upsert");
    writer
        .upsert_enis(&[eni("eni-1", "vpc-1", "subnet-1")])
        .await
        .expect("enis upsert");
    writer
        .upsert_has_sg_edges(&[HasSgEdge {
            eni_id: "eni-1".to_string(),
            security_group_id: "sg-1".to_string(),
        }])
        .await
        .expect("has_sg edges upsert");

    // Assert
    assert_eq!(node_count(&graph, "VPC").await, 1);
    assert_eq!(node_count(&graph, "Subnet").await, 1);
    assert_eq!(node_count(&graph, "SecurityGroup").await, 1);
    assert_eq!(node_count(&graph, "ENI").await, 1);
    assert_eq!(relationship_count(&graph, "HAS_SG").await, 1);
}

#[tokio::test]
#[ignore]
async fn write_batch_twice_is_idempotent_node_and_edge_counts_unchanged() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());
    let enis = [eni("eni-1", "vpc-1", "subnet-1")];
    let security_groups = [security_group("sg-1", "vpc-1", "web")];
    let has_sg_edges = [HasSgEdge {
        eni_id: "eni-1".to_string(),
        security_group_id: "sg-1".to_string(),
    }];

    // Act
    for _ in 0..2 {
        writer
            .upsert_security_groups(&security_groups)
            .await
            .expect("security groups upsert");
        writer.upsert_enis(&enis).await.expect("enis upsert");
        writer
            .upsert_has_sg_edges(&has_sg_edges)
            .await
            .expect("has_sg edges upsert");
    }

    // Assert
    assert_eq!(node_count(&graph, "ENI").await, 1);
    assert_eq!(node_count(&graph, "SecurityGroup").await, 1);
    assert_eq!(relationship_count(&graph, "HAS_SG").await, 1);
}

#[tokio::test]
#[ignore]
async fn write_batch_second_run_with_changed_property_updates_in_place_without_duplicating() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());
    let mut record = eni("eni-1", "vpc-1", "subnet-1");

    // Act
    writer
        .upsert_enis(std::slice::from_ref(&record))
        .await
        .expect("first eni upsert");
    record.private_ip = "10.0.0.99".to_string();
    writer
        .upsert_enis(std::slice::from_ref(&record))
        .await
        .expect("second eni upsert");

    // Assert
    assert_eq!(node_count(&graph, "ENI").await, 1);
    let mut stream = graph
        .execute(query(
            "MATCH (n:ENI {id: 'eni-1'}) RETURN n.private_ip AS private_ip",
        ))
        .await
        .expect("eni query succeeds");
    let row = stream
        .next()
        .await
        .expect("row streams")
        .expect("eni row present");
    assert_eq!(
        row.get::<String>("private_ip").expect("string value"),
        "10.0.0.99"
    );
}

#[tokio::test]
#[ignore]
async fn write_nacl_rules_with_distinct_rule_numbers_creates_distinct_has_rule_edges() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());
    writer
        .upsert_network_acls(&[network_acl("acl-1", "vpc-1")])
        .await
        .expect("network acl upsert");
    let rules = vec![
        NaclRule {
            rule_number: 100,
            direction: Direction::Ingress,
            protocol: "tcp".to_string(),
            port_range: Some(PortRange::new(22, 22).expect("valid port range")),
            cidr: "10.0.0.0/8".to_string(),
            action: Action::Deny,
        },
        NaclRule {
            rule_number: 200,
            direction: Direction::Ingress,
            protocol: "tcp".to_string(),
            port_range: Some(PortRange::new(22, 22).expect("valid port range")),
            cidr: "10.0.0.0/8".to_string(),
            action: Action::Allow,
        },
    ];
    let batches = [NaclRuleBatch {
        network_acl_id: "acl-1",
        rules: &rules,
    }];

    // Act
    writer
        .upsert_has_rules(&batches)
        .await
        .expect("has_rule upsert");

    // Assert
    assert_eq!(relationship_count(&graph, "HAS_RULE").await, 2);
    let mut stream = graph
        .execute(query(
            "MATCH ()-[r:HAS_RULE]->() RETURN r.rule_number AS rule_number ORDER BY r.rule_number",
        ))
        .await
        .expect("has_rule query succeeds");
    let mut rule_numbers = Vec::new();
    while let Some(row) = stream.next().await.expect("row streams") {
        rule_numbers.push(row.get::<i64>("rule_number").expect("int value"));
    }
    assert_eq!(rule_numbers, vec![100, 200]);
}

#[tokio::test]
#[ignore]
async fn write_sg_rule_unresolved_reference_is_queryable_with_resolved_false() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());
    writer
        .upsert_security_groups(&[security_group("sg-1", "vpc-1", "web")])
        .await
        .expect("security group upsert");
    let rules = vec![SgRule {
        direction: Direction::Egress,
        protocol: "tcp".to_string(),
        port_range: Some(PortRange::new(443, 443).expect("valid port range")),
        target: RuleTarget::SecurityGroupRef {
            security_group_id: "sg-cross-account".to_string(),
        },
        resolved: false,
    }];
    let batches = [SgRuleBatch {
        security_group_id: "sg-1",
        rules: &rules,
    }];

    // Act
    writer
        .upsert_allows_egress_rules(&batches)
        .await
        .expect("allows_egress upsert");

    // Assert
    assert_eq!(relationship_count(&graph, "ALLOWS_EGRESS").await, 1);
    let mut stream = graph
        .execute(query(
            "MATCH ()-[r:ALLOWS_EGRESS]->() RETURN r.resolved AS resolved",
        ))
        .await
        .expect("allows_egress query succeeds");
    let row = stream
        .next()
        .await
        .expect("row streams")
        .expect("allows_egress row present");
    assert_eq!(row.get::<bool>("resolved").expect("bool value"), false);
}

#[tokio::test]
#[ignore]
async fn write_sg_rule_resolved_reference_to_real_group_creates_real_edge() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());
    writer
        .upsert_security_groups(&[
            security_group("sg-1", "vpc-1", "web"),
            security_group("sg-2", "vpc-1", "db"),
        ])
        .await
        .expect("security groups upsert");
    let rules = vec![SgRule {
        direction: Direction::Egress,
        protocol: "tcp".to_string(),
        port_range: Some(PortRange::new(5432, 5432).expect("valid port range")),
        target: RuleTarget::SecurityGroupRef {
            security_group_id: "sg-2".to_string(),
        },
        resolved: true,
    }];
    let batches = [SgRuleBatch {
        security_group_id: "sg-1",
        rules: &rules,
    }];

    // Act
    writer
        .upsert_allows_egress_rules(&batches)
        .await
        .expect("allows_egress upsert");

    // Assert
    assert_eq!(relationship_count(&graph, "ALLOWS_EGRESS").await, 1);
    let mut stream = graph
        .execute(query(
            "MATCH (a:SecurityGroup {id: 'sg-1'})-[r:ALLOWS_EGRESS]->(b:SecurityGroup) \
             RETURN b.id AS target_id",
        ))
        .await
        .expect("allows_egress query succeeds");
    let row = stream
        .next()
        .await
        .expect("row streams")
        .expect("allows_egress row present");
    assert_eq!(
        row.get::<String>("target_id").expect("string value"),
        "sg-2"
    );
}

#[tokio::test]
#[ignore]
async fn write_sg_rule_resolved_reference_to_missing_group_returns_graph_write_error() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());
    writer
        .upsert_security_groups(&[security_group("sg-1", "vpc-1", "web")])
        .await
        .expect("security group upsert");
    // "sg-missing" is never upserted, but resolved: true claims it exists.
    let rules = vec![SgRule {
        direction: Direction::Egress,
        protocol: "tcp".to_string(),
        port_range: Some(PortRange::new(5432, 5432).expect("valid port range")),
        target: RuleTarget::SecurityGroupRef {
            security_group_id: "sg-missing".to_string(),
        },
        resolved: true,
    }];
    let batches = [SgRuleBatch {
        security_group_id: "sg-1",
        rules: &rules,
    }];

    // Act
    let result = writer.upsert_allows_egress_rules(&batches).await;

    // Assert
    let error = result.expect_err("resolved reference to a missing group should error");
    assert!(error.to_string().contains("ALLOWS_EGRESS"));
}

#[tokio::test]
#[ignore]
async fn write_routes_to_edge_with_inconsistent_resolved_and_target_returns_graph_write_error() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());
    writer
        .upsert_vpcs(&[vpc("vpc-1")])
        .await
        .expect("vpc upsert");
    writer
        .upsert_route_tables(&[route_table("rtb-1", "vpc-1")])
        .await
        .expect("route table upsert");
    // Inconsistent: target_vpc_id is Some (claims resolved) but resolved is false.
    let edges = [RoutesToEdge {
        route_table_id: "rtb-1".to_string(),
        destination_cidr: "10.0.0.0/16".to_string(),
        target_vpc_id: Some("vpc-1".to_string()),
        resolved: false,
    }];

    // Act
    let result = writer.upsert_routes_to_edges(&edges).await;

    // Assert
    let error = result.expect_err("inconsistent resolved/target_vpc_id should error");
    assert!(error.to_string().contains("ROUTES_TO"));
}

#[tokio::test]
#[ignore]
async fn write_batch_with_missing_endpoint_node_returns_graph_write_error() {
    // Arrange
    let (_container, graph) = start_neo4j().await;
    seed_migrations(&graph).await;
    let writer = Neo4jGraphWriter::new(graph.clone());
    // Neither "eni-missing" nor "sg-missing" has been upserted as a node.
    let edges = [HasSgEdge {
        eni_id: "eni-missing".to_string(),
        security_group_id: "sg-missing".to_string(),
    }];

    // Act
    let result = writer.upsert_has_sg_edges(&edges).await;

    // Assert
    let error = result.expect_err("missing endpoints should error");
    assert!(error.to_string().contains("HAS_SG"));
}
