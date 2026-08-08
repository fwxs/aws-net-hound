//! Idempotent cypher migration runner.
//!
//! Migration files under `migrations/` at the repo root are embedded at
//! compile time so the deployed binary has no filesystem dependency. Applied
//! versions are tracked in Neo4j as `(:SchemaMigration {version, applied_at})`
//! nodes, guarded by a uniqueness constraint this module bootstraps itself
//! (it cannot come from a migration file it is meant to track).

use std::collections::HashSet;

use neo4rs::{query, Graph};
use tracing::{debug, info};

use crate::error::MigrationError;

/// Hand-maintained table of migration files. Order here does not matter —
/// [`run`] sorts by each filename's parsed numeric prefix, not table or
/// lexicographic order.
const MIGRATION_FILES: &[(&str, &str)] = &[
    (
        "0001_constraints.cypher",
        include_str!("../../../migrations/0001_constraints.cypher"),
    ),
    (
        "0002_indexes.cypher",
        include_str!("../../../migrations/0002_indexes.cypher"),
    ),
];

const SCHEMA_MIGRATION_CONSTRAINT: &str = "CREATE CONSTRAINT schema_migration_version_unique IF NOT EXISTS FOR (n:SchemaMigration) REQUIRE n.version IS UNIQUE";

/// Which migration versions [`run`] applied versus found already recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationSummary {
    pub applied: Vec<u32>,
    pub skipped: Vec<u32>,
}

/// Applies every embedded migration not yet recorded in `SchemaMigration`,
/// in ascending version order, to a clean or partially-migrated database.
pub async fn run(graph: &Graph) -> Result<MigrationSummary, MigrationError> {
    bootstrap_schema_migration_constraint(graph).await?;
    let already_applied = read_applied_versions(graph).await?;

    let mut summary = MigrationSummary::default();

    for (version, filename, content) in ordered_migrations()? {
        if already_applied.contains(&version) {
            debug!(version, filename, "migration already applied, skipping");
            summary.skipped.push(version);
            continue;
        }

        apply_version(graph, version, content).await?;
        info!(version, filename, "applied migration");
        summary.applied.push(version);
    }

    Ok(summary)
}

/// Applies one migration version's statements in a single transaction, then
/// records the version in a second transaction. [`run`] calls this for each
/// pending embedded migration; it is exposed so integration tests can
/// exercise a deliberately failing statement, which the embedded migration
/// files (by construction) never contain.
///
/// The record can't share a transaction with the statements: Neo4j forbids
/// a data write (the `SchemaMigration` `MERGE`) after a schema modification
/// (`CREATE CONSTRAINT` / `CREATE INDEX`) in the same transaction. This still
/// never records a version whose statements didn't fully commit — if the
/// statements fail, we return before recording — and since every statement
/// is `IF NOT EXISTS`-idempotent, a crash between the two transactions is
/// safe to retry: re-running the statements is a no-op, and the record then
/// goes through.
pub async fn apply_version(
    graph: &Graph,
    version: u32,
    cypher_source: &str,
) -> Result<(), MigrationError> {
    let mut txn = graph
        .start_txn()
        .await
        .map_err(|source| MigrationError::StartTransaction { version, source })?;

    for (statement_index, statement) in split_statements(cypher_source).into_iter().enumerate() {
        debug!(version, statement_index, "applying statement");
        if let Err(source) = txn.run(query(&statement)).await {
            let _ = txn.rollback().await;
            return Err(MigrationError::StatementFailed {
                version,
                statement_index,
                source,
            });
        }
    }

    txn.commit()
        .await
        .map_err(|source| MigrationError::Commit { version, source })?;

    record_version(graph, version).await
}

async fn record_version(graph: &Graph, version: u32) -> Result<(), MigrationError> {
    let mut txn = graph
        .start_txn()
        .await
        .map_err(|source| MigrationError::StartTransaction { version, source })?;

    let record =
        query("MERGE (n:SchemaMigration {version: $version}) SET n.applied_at = datetime()")
            .param("version", i64::from(version));

    if let Err(source) = txn.run(record).await {
        let _ = txn.rollback().await;
        return Err(MigrationError::RecordVersion { version, source });
    }

    txn.commit()
        .await
        .map_err(|source| MigrationError::Commit { version, source })
}

/// Parses the numeric prefix (the digits before the first `_`) out of a
/// migration filename, e.g. `"0002_indexes.cypher"` -> `2`.
fn parse_version_prefix(filename: &str) -> Result<u32, MigrationError> {
    filename
        .split('_')
        .next()
        .filter(|prefix| !prefix.is_empty())
        .and_then(|prefix| prefix.parse::<u32>().ok())
        .ok_or_else(|| MigrationError::MalformedFilename {
            filename: filename.to_string(),
        })
}

fn ordered_migrations() -> Result<Vec<(u32, &'static str, &'static str)>, MigrationError> {
    let mut migrations = MIGRATION_FILES
        .iter()
        .map(|(filename, content)| {
            parse_version_prefix(filename).map(|version| (version, *filename, *content))
        })
        .collect::<Result<Vec<_>, _>>()?;

    migrations.sort_by_key(|(version, _, _)| *version);
    Ok(migrations)
}

/// Splits a migration file's source on `;` per the delimiter contract
/// documented in `migrations/0001_constraints.cypher`'s header, stripping
/// `//` comment lines and discarding empty statements.
fn split_statements(source: &str) -> Vec<String> {
    // Comment lines are stripped before splitting on `;` — a `;` character
    // can legitimately appear inside a comment's prose (as it does in this
    // file's own header), and splitting first would break the statement
    // that comment precedes.
    let without_comments = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    without_comments
        .split(';')
        .map(|statement| statement.trim().to_string())
        .filter(|statement| !statement.is_empty())
        .collect()
}

async fn bootstrap_schema_migration_constraint(graph: &Graph) -> Result<(), MigrationError> {
    graph
        .run(query(SCHEMA_MIGRATION_CONSTRAINT))
        .await
        .map_err(|source| MigrationError::Bootstrap { source })
}

async fn read_applied_versions(graph: &Graph) -> Result<HashSet<u32>, MigrationError> {
    let mut stream = graph
        .execute(query(
            "MATCH (n:SchemaMigration) RETURN n.version AS version",
        ))
        .await
        .map_err(|source| MigrationError::ReadAppliedVersions { source })?;

    let mut versions = HashSet::new();
    while let Some(row) = stream
        .next()
        .await
        .map_err(|source| MigrationError::ReadAppliedVersions { source })?
    {
        let version: i64 = row
            .get("version")
            .map_err(|source| MigrationError::ReadAppliedVersionsDeserialize { source })?;
        versions.insert(version as u32);
    }
    Ok(versions)
}

#[cfg(test)]
// Test-only assertions on a known-good parse; unwrap is the clearest way to
// express "this must succeed" without adding error-handling noise to a test.
#[allow(clippy::unwrap_used)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn migration_ordering_sorts_by_numeric_prefix_not_lexicographically() {
        // Arrange
        let files: &[(&str, &str)] = &[("0010_later.cypher", "b"), ("0009_earlier.cypher", "a")];

        // Act
        let mut parsed: Vec<(u32, &str, &str)> = files
            .iter()
            .map(|(filename, content)| {
                (parse_version_prefix(filename).unwrap(), *filename, *content)
            })
            .collect();
        parsed.sort_by_key(|(version, _, _)| *version);

        // Assert
        assert_eq!(
            parsed.iter().map(|(v, _, _)| *v).collect::<Vec<_>>(),
            vec![9, 10]
        );
    }

    #[test]
    fn parse_version_prefix_malformed_filename_returns_error() {
        // Arrange
        let filename = "constraints.cypher";

        // Act
        let result = parse_version_prefix(filename);

        // Assert
        assert!(matches!(
            result,
            Err(MigrationError::MalformedFilename { filename }) if filename == "constraints.cypher"
        ));
    }

    #[test]
    fn split_statements_ignores_semicolon_inside_comment_prose() {
        // Arrange
        let source = "// terminated by a semicolon `;` in prose, not code\nCREATE CONSTRAINT a IF NOT EXISTS FOR (n:A) REQUIRE n.id IS UNIQUE;\n";

        // Act
        let statements = split_statements(source);

        // Assert
        assert_eq!(
            statements,
            vec!["CREATE CONSTRAINT a IF NOT EXISTS FOR (n:A) REQUIRE n.id IS UNIQUE"]
        );
    }

    #[test]
    fn split_statements_ignores_comments_and_blank_lines() {
        // Arrange
        let source = "// header comment\n\nCREATE CONSTRAINT a IF NOT EXISTS FOR (n:A) REQUIRE n.id IS UNIQUE;\n\n// another comment\nCREATE CONSTRAINT b IF NOT EXISTS FOR (n:B) REQUIRE n.id IS UNIQUE;\n";

        // Act
        let statements = split_statements(source);

        // Assert
        assert_eq!(statements.len(), 2);
        assert_eq!(
            statements[0],
            "CREATE CONSTRAINT a IF NOT EXISTS FOR (n:A) REQUIRE n.id IS UNIQUE"
        );
        assert_eq!(
            statements[1],
            "CREATE CONSTRAINT b IF NOT EXISTS FOR (n:B) REQUIRE n.id IS UNIQUE"
        );
    }
}
