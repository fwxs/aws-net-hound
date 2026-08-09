//! Builds the shared `aws_sdk_ec2::Client` every Milestone 1 ingestion task
//! uses, so region and retry behaviour cannot diverge between call sites.

use std::time::Duration;

use aws_config::meta::region::ProvideRegion;
use aws_config::profile::region::ProfileFileRegionProvider;
use aws_config::retry::RetryConfig;
use aws_config::timeout::TimeoutConfig;
use aws_config::{BehaviorVersion, Region};
use tracing::info;

use crate::error::IngestError;

use super::IngestConfig;

/// Maximum attempts (including the first) the Smithy runtime makes for a
/// single AWS API call before giving up. `DescribeNetworkInterfaces` over a
/// large VPC paginates for many pages and a mid-size account routinely
/// trips `RequestLimitExceeded`; the SDK's own exponential backoff with
/// jitter already classifies that as retryable, so this is the only retry
/// knob this function needs to set.
const MAX_ATTEMPTS: u32 = 8;

/// Upper bound on a single attempt's duration. There is deliberately no
/// overall `operation_timeout` alongside it: a total budget shorter than
/// `MAX_ATTEMPTS` attempts' worth of backoff would silently cut retries
/// short before they're exhausted — exactly the partial-ingestion failure
/// this function exists to prevent.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

/// Builds an `aws_sdk_ec2::Client` with a resolved region and the SDK's
/// standard retry policy configured.
///
/// # Region resolution
///
/// In order, the first non-empty source wins:
///
/// 1. `config.region`, if set.
/// 2. The `AWS_REGION` environment variable, falling back to
///    `AWS_DEFAULT_REGION`.
/// 3. The active AWS profile's `region` setting.
///
/// EC2 instance metadata (IMDS) is deliberately not consulted for region:
/// unlike credentials, an audit's region must come from an explicit,
/// auditable source rather than wherever the process happens to run. If
/// none of the above resolves a non-empty region, this returns
/// [`IngestError::RegionNotResolved`] — never a compiled-in default.
///
/// # Retry
///
/// Configured entirely through the SDK's own [`RetryConfig::standard`],
/// which already classifies `RequestLimitExceeded` and 429/503 as
/// retryable and applies exponential backoff with jitter; no hand-written
/// backoff loop.
pub async fn build_ec2_client(config: &IngestConfig) -> Result<aws_sdk_ec2::Client, IngestError> {
    let profile_region = ProfileFileRegionProvider::builder().build().region().await;

    build_ec2_client_from_sources(
        config.region.as_deref(),
        std::env::var("AWS_REGION").ok().as_deref(),
        std::env::var("AWS_DEFAULT_REGION").ok().as_deref(),
        profile_region.as_ref().map(|region| region.as_ref()),
    )
    .await
}

/// Does the actual client construction once every region candidate has
/// already been read from its source. Split out from [`build_ec2_client`]
/// so tests can supply each candidate directly instead of depending on the
/// process environment or an on-disk profile — see
/// `build_ec2_client_with_explicit_region_uses_that_region` and
/// `build_ec2_client_without_any_region_returns_region_not_resolved`.
async fn build_ec2_client_from_sources(
    explicit: Option<&str>,
    aws_region_env: Option<&str>,
    aws_default_region_env: Option<&str>,
    profile_region: Option<&str>,
) -> Result<aws_sdk_ec2::Client, IngestError> {
    let region = resolve_region(
        explicit,
        aws_region_env,
        aws_default_region_env,
        profile_region,
    )
    .ok_or(IngestError::RegionNotResolved)?;

    info!(%region, "resolved AWS region for EC2 client");

    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region))
        .retry_config(RetryConfig::standard().with_max_attempts(MAX_ATTEMPTS))
        .timeout_config(
            TimeoutConfig::builder()
                .operation_attempt_timeout(ATTEMPT_TIMEOUT)
                .build(),
        )
        .load()
        .await;

    Ok(aws_sdk_ec2::Client::new(&sdk_config))
}

/// Picks the first non-empty candidate, in priority order: `explicit`,
/// `aws_region_env`, `aws_default_region_env`, `profile_region`. An
/// empty-string candidate is treated as absent so e.g. an explicitly blank
/// `IngestConfig::region` falls through to the next source instead of
/// silently producing an unusable client.
fn resolve_region(
    explicit: Option<&str>,
    aws_region_env: Option<&str>,
    aws_default_region_env: Option<&str>,
    profile_region: Option<&str>,
) -> Option<String> {
    [
        explicit,
        aws_region_env,
        aws_default_region_env,
        profile_region,
    ]
    .into_iter()
    .find_map(|candidate| candidate.filter(|value| !value.is_empty()))
    .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[tokio::test]
    async fn build_ec2_client_with_explicit_region_uses_that_region() {
        // Arrange / Act
        let result = build_ec2_client_from_sources(Some("eu-west-1"), None, None, None).await;

        // Assert
        let client = match result {
            Ok(client) => client,
            Err(err) => panic!("expected an explicit region to build a client, got {err:?}"),
        };
        assert_eq!(client.config().region(), Some(&Region::new("eu-west-1")));
    }

    #[tokio::test]
    async fn build_ec2_client_without_any_region_returns_region_not_resolved() {
        // Arrange / Act
        let result = build_ec2_client_from_sources(None, None, None, None).await;

        // Assert
        assert!(matches!(result, Err(IngestError::RegionNotResolved)));
    }

    #[test]
    fn resolve_region_treats_empty_explicit_region_as_absent() {
        // Arrange / Act
        let region = resolve_region(Some(""), None, None, Some("ap-south-1"));

        // Assert
        assert_eq!(region, Some("ap-south-1".to_string()));
    }

    #[test]
    fn resolve_region_prefers_aws_region_over_aws_default_region() {
        // Arrange / Act
        let region = resolve_region(None, Some("us-west-2"), Some("us-east-2"), None);

        // Assert
        assert_eq!(region, Some("us-west-2".to_string()));
    }

    #[test]
    fn resolve_region_with_no_source_returns_none() {
        // Arrange / Act
        let region = resolve_region(None, None, None, None);

        // Assert
        assert_eq!(region, None);
    }
}
