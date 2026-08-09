//! AWS resource ingestion for Milestone 1.
//!
//! [`aws_client::build_ec2_client`] is the one constructor every later
//! ingestion task in this milestone builds on, so region and retry
//! behaviour cannot diverge silently between call sites.

pub mod aws_client;
pub mod error;

/// Configuration shared by ingestion: AWS client construction now, and the
/// Neo4j connection settings [`crate::migrations`]'s caller and M1-T6's
/// `GraphWriter` implementation will need.
///
/// Deliberately carries no credential of any kind. AWS credentials come
/// only from the standard `aws-config` provider chain (environment,
/// profile, instance/container role); there is no field here that could
/// hold an access key, secret key, session token, or password.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestConfig {
    /// Explicit AWS region to ingest. `None` resolves the region from the
    /// standard chain instead — see [`aws_client::build_ec2_client`].
    pub region: Option<String>,

    /// Neo4j connection URI (e.g. `bolt://localhost:7687`), consumed by
    /// the `GraphWriter` implementation this milestone adds later. Holds
    /// no auth: a URI names a location, not a credential.
    pub neo4j_uri: Option<String>,
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn ingest_config_default_carries_no_credentials() {
        // Arrange
        let config = IngestConfig::default();

        // Act / Assert: exhaustive destructure — a field added to
        // `IngestConfig` breaks this match, forcing whoever adds it to
        // confirm here that it can't hold a secret.
        let IngestConfig { region, neo4j_uri } = config;
        assert_eq!(region, None);
        assert_eq!(neo4j_uri, None);
    }
}
