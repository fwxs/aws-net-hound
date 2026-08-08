//! Error types for the migration runner and the `ports` trait contracts.

use thiserror::Error;

/// Errors a [`crate::ports::GraphWriter`] implementation can return.
///
/// Reserved for genuine write failures (transport, driver errors) — an
/// unresolved cross-account reference is not an error, see `resolved: bool`
/// on the relevant edge properties in `crates/core/docs/schema.md`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GraphWriteError {
    /// The underlying write to Neo4j failed.
    #[error("failed to write to the graph: {source}")]
    Write {
        #[source]
        source: neo4rs::Error,
    },
}

/// Errors a [`crate::ports::Resolver`] implementation can return.
///
/// Reserved for genuine failures only. An unresolvable cross-account
/// reference (expected in local-audit mode) is a successful outcome —
/// see [`crate::ports::ResolvedReference`] — not an `Err` here.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ResolveError {
    /// A transport-level failure occurred while attempting to resolve a
    /// reference (e.g. the Neo4j driver call failed).
    #[error("transport failure while resolving a reference: {source}")]
    Transport {
        #[source]
        source: neo4rs::Error,
    },

    /// The input given to the resolver was malformed and could not be
    /// interpreted as a resolvable reference.
    #[error("malformed input while resolving a reference: {reason}")]
    MalformedInput { reason: String },
}

/// Errors a [`crate::ports::Evaluator`] implementation can return.
///
/// Deliberately free of any Neo4j/driver type: the `Evaluator` trait
/// operates only on already-materialized `core::domain` structs, and its
/// error type must not reintroduce a database dependency.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvaluationError {
    /// The path candidate had no hops to evaluate.
    #[error("path candidate is empty, no hops to evaluate")]
    EmptyPath,

    /// A hop within the path candidate was structurally invalid.
    #[error("path candidate has an invalid hop at index {index}: {reason}")]
    InvalidHop { index: usize, reason: String },
}

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
