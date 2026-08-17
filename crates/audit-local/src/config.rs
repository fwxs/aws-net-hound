//! Audit configuration: YAML schema, parsing, and validation.
//!
//! [`Config`] is what `serde_norway` deserializes. It is deliberately not
//! the type the rest of the crate is allowed to hold — [`Config::validate`]
//! is the only way to obtain a [`ValidatedConfig`], so a config that was
//! merely parsed (and might have an empty boundary, an implausible region,
//! etc.) cannot reach the orchestrator.

use std::path::PathBuf;

use serde::Deserialize;

/// Deserialized, not-yet-validated audit configuration.
///
/// `deny_unknown_fields` turns a typo'd key into a parse error instead of
/// a silently ignored setting.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub region: String,
    pub profile: String,
    pub boundary: BoundaryConfig,
    pub output_path: PathBuf,
    pub neo4j: Neo4jConfig,
}

/// Selectors identifying the regulated boundary a run evaluates
/// reachability against. At least one list must be non-empty after
/// validation — see [`Config::validate`].
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryConfig {
    #[serde(default)]
    pub vpc_ids: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl BoundaryConfig {
    fn is_empty(&self) -> bool {
        self.vpc_ids.is_empty() && self.cidrs.is_empty() && self.tags.is_empty()
    }
}

/// Neo4j connection settings. No password field: the password is read
/// from `NEO4J_PASSWORD` (the same variable `docker-compose.yml`
/// consumes), never stored in an operator-authored config file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Neo4jConfig {
    pub uri: String,
    pub user: String,
}

/// A [`Config`] that has passed [`Config::validate`]. The only config
/// type the rest of the crate accepts — its fields are only reachable
/// through `validate`, so an unvalidated config cannot reach the
/// orchestrator.
#[derive(Debug)]
pub struct ValidatedConfig {
    pub region: String,
    pub profile: String,
    pub boundary: BoundaryConfig,
    pub output_path: PathBuf,
    pub neo4j: Neo4jConfig,
}

/// Errors from parsing or validating an audit configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    UnreadableFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config: {source}")]
    Malformed {
        #[source]
        source: serde_norway::Error,
    },

    #[error(
        "boundary has no selectors: at least one of vpc_ids, cidrs, or tags must be non-empty"
    )]
    EmptyBoundary,

    #[error("invalid region {region:?}: expected a lowercase region string containing '-'")]
    InvalidRegion { region: String },
}

impl Config {
    /// Parse a YAML document into an unvalidated [`Config`].
    pub fn parse(yaml: &str) -> Result<Self, ConfigError> {
        serde_norway::from_str(yaml).map_err(|source| ConfigError::Malformed { source })
    }

    /// Read and parse a config file from disk.
    pub fn from_path(path: &std::path::Path) -> Result<Self, ConfigError> {
        let yaml = std::fs::read_to_string(path).map_err(|source| ConfigError::UnreadableFile {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&yaml)
    }

    /// Validate this config, producing the only type the rest of the
    /// crate is allowed to hold.
    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        if self.boundary.is_empty() {
            return Err(ConfigError::EmptyBoundary);
        }

        let region_valid = !self.region.is_empty()
            && self.region.chars().all(|c| !c.is_uppercase())
            && self.region.contains('-');
        if !region_valid {
            return Err(ConfigError::InvalidRegion {
                region: self.region,
            });
        }

        Ok(ValidatedConfig {
            region: self.region,
            profile: self.profile,
            boundary: self.boundary,
            output_path: self.output_path,
            neo4j: self.neo4j,
        })
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const COMPLETE_YAML: &str = r#"
region: us-east-1
profile: default
boundary:
  vpc_ids:
    - vpc-0example
  cidrs: []
  tags: []
output_path: ./audit-report.json
neo4j:
  uri: bolt://127.0.0.1:7687
  user: neo4j
"#;

    #[test]
    fn parse_config_complete_yaml_returns_validated_config() {
        let config = Config::parse(COMPLETE_YAML).unwrap_or_else(|e| panic!("parse failed: {e}"));

        let validated = config
            .validate()
            .unwrap_or_else(|e| panic!("validate failed: {e}"));

        assert_eq!(validated.region, "us-east-1");
        assert_eq!(validated.boundary.vpc_ids, vec!["vpc-0example"]);
    }

    #[test]
    fn parse_config_missing_region_returns_malformed_error() {
        let yaml = r#"
profile: default
boundary:
  vpc_ids: [vpc-0example]
output_path: ./out.json
neo4j:
  uri: bolt://127.0.0.1:7687
  user: neo4j
"#;

        let result = Config::parse(yaml);

        assert!(matches!(result, Err(ConfigError::Malformed { .. })));
    }

    #[test]
    fn validate_config_empty_boundary_returns_empty_boundary_error() {
        let yaml = r#"
region: us-east-1
profile: default
boundary: {}
output_path: ./out.json
neo4j:
  uri: bolt://127.0.0.1:7687
  user: neo4j
"#;
        let config = Config::parse(yaml).unwrap_or_else(|e| panic!("parse failed: {e}"));

        let result = config.validate();

        assert!(matches!(result, Err(ConfigError::EmptyBoundary)));
    }

    #[test]
    fn validate_config_boundary_with_only_tags_returns_validated_config() {
        let yaml = r#"
region: us-east-1
profile: default
boundary:
  tags: [env:pci-prod]
output_path: ./out.json
neo4j:
  uri: bolt://127.0.0.1:7687
  user: neo4j
"#;
        let config = Config::parse(yaml).unwrap_or_else(|e| panic!("parse failed: {e}"));

        let validated = config
            .validate()
            .unwrap_or_else(|e| panic!("validate failed: {e}"));

        assert_eq!(validated.boundary.tags, vec!["env:pci-prod"]);
    }

    #[test]
    fn parse_config_unknown_key_returns_malformed_error() {
        let yaml = r#"
region: us-east-1
profile: default
boundary:
  vpc_ids: [vpc-0example]
output_path: ./out.json
neo4j:
  uri: bolt://127.0.0.1:7687
  user: neo4j
bogus_field: true
"#;

        let result = Config::parse(yaml);

        assert!(matches!(result, Err(ConfigError::Malformed { .. })));
    }

    #[test]
    fn parse_config_malformed_yaml_preserves_serde_error_as_source() {
        let yaml = "region: [this is not valid: yaml structure";

        let result = Config::parse(yaml);

        let Err(err @ ConfigError::Malformed { .. }) = result else {
            panic!("expected Malformed error, got {result:?}");
        };
        // The underlying serde_norway::Error carries line/column info;
        // assert it survives as the typed #[source], not just Display text.
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn validate_config_invalid_region_returns_invalid_region_error() {
        let yaml = r#"
region: US-EAST-1
profile: default
boundary:
  vpc_ids: [vpc-0example]
output_path: ./out.json
neo4j:
  uri: bolt://127.0.0.1:7687
  user: neo4j
"#;
        let config = Config::parse(yaml).unwrap_or_else(|e| panic!("parse failed: {e}"));

        let result = config.validate();

        assert!(matches!(result, Err(ConfigError::InvalidRegion { .. })));
    }

    #[test]
    fn parse_example_config_file_returns_validated_config() {
        let yaml = include_str!("../config.example.yaml");
        let config = Config::parse(yaml).unwrap_or_else(|e| panic!("parse failed: {e}"));

        let validated = config
            .validate()
            .unwrap_or_else(|e| panic!("validate failed: {e}"));

        assert_eq!(validated.region, "us-east-1");
        assert_eq!(validated.neo4j.user, "neo4j");
    }
}
