//! `run` orchestration (M3-T5): preflight -> connect/migrate -> upsert
//! boundary -> ingest -> evaluate, strictly sequential.
//!
//! Ordering is load-bearing, not incidental: migrations must run before any
//! write (uniqueness constraints must exist first, or re-ingestion
//! duplicates nodes), the boundary must exist before evaluation asks
//! questions about it, and ingestion must fully complete before evaluation
//! reads the graph it wrote.

use std::time::Instant;

use anyhow::Context;
use aws_net_hound_core::domain::{Reachability, ReachabilityFinding};
use aws_net_hound_core::evaluate::{
    assemble_candidates, BoundarySelectors, RuleIntersectionEvaluator,
};
use aws_net_hound_core::graph::neo4j::Neo4jGraphWriter;
use aws_net_hound_core::ingest::aws_client::{build_sdk_config, resolve_account_id};
use aws_net_hound_core::ingest::pipeline::run_full_ingest_with_client;
use aws_net_hound_core::ingest::IngestConfig;
use aws_net_hound_core::ports::{Evaluator, GraphWriter, RegulatedBoundaryRecord};
use neo4rs::{ConfigBuilder, Graph};
use tracing::{info, warn};

use crate::config::ValidatedConfig;
use crate::{preflight, Outcome};

/// Runs the full audit pipeline against an already-validated config,
/// building a real AWS EC2 client and resolving the calling account id
/// before delegating every other stage to [`run_with_ec2_client`].
pub async fn run(config: ValidatedConfig) -> anyhow::Result<Outcome> {
    preflight::run().await.context("stage: preflight")?;

    let ingest_config = IngestConfig {
        region: Some(config.region.clone()),
        neo4j_uri: None,
    };
    let sdk_config = build_sdk_config(&ingest_config)
        .await
        .context("stage: ingest")?;
    let account_id = resolve_account_id(&sdk_config)
        .await
        .context("stage: ingest")?;
    let client = aws_sdk_ec2::Client::new(&sdk_config);

    run_with_ec2_client(config, &client, &account_id).await
}

/// Does every stage after AWS client/account-id construction. Split out so
/// `tests/run_integration.rs` can drive the pipeline against an
/// `aws-smithy-mocks` client and a fixed account id, mirroring the
/// `run_full_ingest`/`run_full_ingest_with_client` split `core::ingest`
/// already uses for the same reason: there is no way to inject a mock
/// client through `run`'s single `ValidatedConfig` argument otherwise.
pub async fn run_with_ec2_client(
    config: ValidatedConfig,
    client: &aws_sdk_ec2::Client,
    account_id: &str,
) -> anyhow::Result<Outcome> {
    let graph = connect(&config).await.context("stage: connect")?;

    info!(stage = "migrate", "starting");
    let migrate_start = Instant::now();
    let summary = aws_net_hound_core::migrations::run(&graph)
        .await
        .context("stage: migrate")?;
    info!(
        stage = "migrate",
        applied = summary.applied.len(),
        skipped = summary.skipped.len(),
        duration_secs = migrate_start.elapsed().as_secs_f64(),
        "completed"
    );

    let writer = Neo4jGraphWriter::new(graph.clone());

    info!(stage = "boundary", "starting");
    let boundary_start = Instant::now();
    let boundary_id = boundary_id(account_id);
    let boundary = RegulatedBoundaryRecord {
        id: boundary_id.clone(),
        account_id: account_id.to_string(),
        name: boundary_id.clone(),
        regime: "unspecified".to_string(),
        description: None,
    };
    writer
        .upsert_regulated_boundaries(&[boundary])
        .await
        .context("stage: boundary")?;
    if !config.boundary.cidrs.is_empty() {
        warn!("boundary cidrs selector is configured but not yet matched against the graph (no Subnet/VPC cidr_block data until a DescribeSubnets/DescribeVpcs collector exists)");
    }
    if !config.boundary.tags.is_empty() {
        warn!("boundary tags selector is configured but not yet matched against the graph (no tag data is ingested)");
    }
    info!(
        stage = "boundary",
        duration_secs = boundary_start.elapsed().as_secs_f64(),
        "completed"
    );

    info!(stage = "ingest", "starting");
    let report = run_full_ingest_with_client(client, account_id, &writer)
        .await
        .context("stage: ingest")?;
    if report.unresolved_references > 0 {
        warn!(
            unresolved_references = report.unresolved_references,
            "unresolved cross-account references"
        );
    }
    info!(
        stage = "ingest",
        ?report.counts,
        unresolved_references = report.unresolved_references,
        duration_secs = report.duration_secs,
        "completed"
    );

    info!(stage = "evaluate (candidate assembly)", "starting");
    let assembly_start = Instant::now();
    let selectors = BoundarySelectors {
        vpc_ids: &config.boundary.vpc_ids,
        cidrs: &config.boundary.cidrs,
        tags: &config.boundary.tags,
    };
    let candidates = assemble_candidates(&graph, &boundary_id, selectors)
        .await
        .context("stage: evaluate (candidate assembly)")?;
    info!(
        stage = "evaluate (candidate assembly)",
        candidates = candidates.len(),
        duration_secs = assembly_start.elapsed().as_secs_f64(),
        "completed"
    );

    info!(stage = "evaluate", "starting");
    let evaluate_start = Instant::now();
    let evaluator = RuleIntersectionEvaluator;
    let mut findings = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        let finding = evaluator
            .evaluate(candidate)
            .await
            .context("stage: evaluate")?;
        findings.push(finding);
    }
    info!(
        stage = "evaluate",
        findings = findings.len(),
        duration_secs = evaluate_start.elapsed().as_secs_f64(),
        "completed"
    );

    Ok(findings_to_outcome(&findings))
}

/// Derives a stable `RegulatedBoundary.id` from the account id. `BoundaryConfig`
/// carries no operator-assigned id/name/regime today (only selector lists) —
/// this is a placeholder pending a config schema addition; see the plan's
/// open items.
fn boundary_id(account_id: &str) -> String {
    format!("boundary-{account_id}")
}

async fn connect(config: &ValidatedConfig) -> anyhow::Result<Graph> {
    let password = std::env::var("NEO4J_PASSWORD").context("NEO4J_PASSWORD is not set")?;

    info!(stage = "connect", "starting");
    let connect_start = Instant::now();
    let neo4j_config = ConfigBuilder::new()
        .uri(config.neo4j.uri.clone())
        .user(config.neo4j.user.clone())
        .password(password)
        .build()
        .context("failed to build the neo4j connection config")?;
    let graph = Graph::connect(neo4j_config)
        .await
        .context("failed to connect to neo4j")?;
    info!(
        stage = "connect",
        duration_secs = connect_start.elapsed().as_secs_f64(),
        "completed"
    );
    Ok(graph)
}

fn findings_to_outcome(findings: &[ReachabilityFinding]) -> Outcome {
    let reachable = findings
        .iter()
        .filter(|finding| matches!(finding.reachability, Reachability::Reachable))
        .count();
    let indeterminate = findings
        .iter()
        .filter(|finding| matches!(finding.reachability, Reachability::Indeterminate { .. }))
        .count();

    if reachable == 0 && indeterminate == 0 {
        Outcome::Clean
    } else {
        Outcome::FindingsPresent {
            reachable,
            indeterminate,
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_net_hound_core::domain::Severity;
    use aws_net_hound_core::evaluate::path::PathEvidence;
    use pretty_assertions::assert_eq;

    use super::*;

    fn sample_finding(reachability: Reachability) -> ReachabilityFinding {
        ReachabilityFinding {
            computed_at: "2026-08-08T00:00:00Z".to_string(),
            source: "eni-0example".to_string(),
            destination_boundary: "boundary-pci-prod".to_string(),
            path_evidence: PathEvidence { steps: Vec::new() },
            reachability,
            severity: Severity::Low,
        }
    }

    #[test]
    fn findings_to_outcome_no_findings_returns_clean() {
        // Arrange
        let findings: Vec<ReachabilityFinding> = Vec::new();

        // Act
        let outcome = findings_to_outcome(&findings);

        // Assert
        assert_eq!(outcome, Outcome::Clean);
    }

    #[test]
    fn findings_to_outcome_one_reachable_returns_findings_present_with_count() {
        // Arrange
        let findings = vec![sample_finding(Reachability::Reachable)];

        // Act
        let outcome = findings_to_outcome(&findings);

        // Assert
        assert_eq!(
            outcome,
            Outcome::FindingsPresent {
                reachable: 1,
                indeterminate: 0,
            }
        );
    }

    #[test]
    fn findings_to_outcome_only_indeterminate_returns_findings_present() {
        // Arrange
        let findings = vec![sample_finding(Reachability::Indeterminate {
            layers: Vec::new(),
        })];

        // Act
        let outcome = findings_to_outcome(&findings);

        // Assert
        assert_eq!(
            outcome,
            Outcome::FindingsPresent {
                reachable: 0,
                indeterminate: 1,
            }
        );
        assert_ne!(outcome, Outcome::Clean);
    }
}
