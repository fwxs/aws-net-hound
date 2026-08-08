//! Error types for the migration runner.

use thiserror::Error;

/// Errors that can occur while ordering, applying, or recording schema
/// migrations against Neo4j.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MigrationError {
    /// A migration filename does not start with a numeric version prefix
    /// (e.g. `0001_constraints.cypher`).
    #[error("migration file name `{filename}` does not start with a numeric version prefix")]
    MalformedFilename { filename: String },

    /// Bootstrapping the uniqueness constraint on `SchemaMigration.version`
    /// failed.
    #[error("failed to bootstrap the schema_migration_version_unique constraint: {source}")]
    Bootstrap {
        #[source]
        source: neo4rs::Error,
    },

    /// Reading the set of already-applied migration versions failed.
    #[error("failed to read applied migration versions: {source}")]
    ReadAppliedVersions {
        #[source]
        source: neo4rs::Error,
    },

    /// A row returned while reading applied migration versions could not be
    /// deserialized.
    #[error("failed to deserialize an applied migration version: {source}")]
    ReadAppliedVersionsDeserialize {
        #[source]
        source: neo4rs::DeError,
    },

    /// Starting the transaction for a migration version failed.
    #[error("failed to start a transaction for migration version {version}: {source}")]
    StartTransaction {
        version: u32,
        #[source]
        source: neo4rs::Error,
    },

    /// A statement within a migration version failed to execute.
    #[error("migration version {version} failed at statement {statement_index}: {source}")]
    StatementFailed {
        version: u32,
        statement_index: usize,
        #[source]
        source: neo4rs::Error,
    },

    /// Recording a migration version as applied failed.
    #[error("failed to record migration version {version} as applied: {source}")]
    RecordVersion {
        version: u32,
        #[source]
        source: neo4rs::Error,
    },

    /// Committing the transaction for a migration version failed.
    #[error("failed to commit migration version {version}: {source}")]
    Commit {
        version: u32,
        #[source]
        source: neo4rs::Error,
    },
}
