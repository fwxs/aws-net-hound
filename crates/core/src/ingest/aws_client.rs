//! Builds the shared `aws_sdk_ec2::Client` every Milestone 1 ingestion task
//! uses, so region and retry behaviour cannot diverge between call sites.

use std::time::Duration;

use aws_config::environment::region::EnvironmentVariableRegionProvider;
use aws_config::meta::region::RegionProviderChain;
use aws_config::profile::region::ProfileFileRegionProvider;
use aws_config::retry::RetryConfig;
use aws_config::timeout::TimeoutConfig;
use aws_config::{BehaviorVersion, Region};
use tracing::info;

use super::error::IngestError;
use super::IngestConfig;

/// Maximum attempts (including the first) the Smithy runtime makes for a
/// single AWS API call before giving up. `DescribeNetworkInterfaces` over a
/// large VPC paginates for many pages and a mid-size account routinely
/// trips `RequestLimitExceeded`; the SDK's own exponential backoff with
/// jitter already classifies that as retryable, so this is the only retry
/// knob this function needs to set.
const MAX_ATTEMPTS: u32 = 8;

/// Builds an `aws_sdk_ec2::Client` with a resolved region and the SDK's
/// standard retry policy configured.
///
/// # Region resolution
///
/// In order, the first source that yields a region wins:
///
/// 1. `config.region`, if set.
/// 2. The `AWS_REGION` environment variable, falling back to
///    `AWS_DEFAULT_REGION`.
/// 3. The active AWS profile's `region` setting.
///
/// EC2 instance metadata (IMDS) is deliberately not consulted for region:
/// unlike credentials, an audit's region must come from an explicit,
/// auditable source rather than wherever the process happens to run. If
/// none of the above resolves a region, this returns
/// [`IngestError::RegionNotResolved`] — never a compiled-in default.
///
/// # Retry
///
/// Configured entirely through the SDK's own [`RetryConfig::standard`],
/// which already classifies `RequestLimitExceeded` and 429/503 as
/// retryable and applies exponential backoff with jitter; no hand-written
/// backoff loop.
pub async fn build_ec2_client(config: &IngestConfig) -> Result<aws_sdk_ec2::Client, IngestError> {
    let region_provider = RegionProviderChain::first_try(config.region.clone().map(Region::new))
        .or_else(EnvironmentVariableRegionProvider::new())
        .or_else(ProfileFileRegionProvider::builder().build());

    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .retry_config(RetryConfig::standard().with_max_attempts(MAX_ATTEMPTS))
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(60))
                .operation_attempt_timeout(Duration::from_secs(20))
                .build(),
        )
        .load()
        .await;

    let region = sdk_config
        .region()
        .cloned()
        .ok_or(IngestError::RegionNotResolved)?;

    info!(%region, "resolved AWS region for EC2 client");

    Ok(aws_sdk_ec2::Client::new(&sdk_config))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[tokio::test]
    async fn build_ec2_client_with_explicit_region_uses_that_region() {
        // Arrange
        let config = IngestConfig {
            region: Some("eu-west-1".to_string()),
            ..IngestConfig::default()
        };

        // Act
        let result = build_ec2_client(&config).await;

        // Assert
        let client = match result {
            Ok(client) => client,
            Err(err) => panic!("expected an explicit region to build a client, got {err:?}"),
        };
        assert_eq!(client.config().region(), Some(&Region::new("eu-west-1")));
    }

    #[tokio::test]
    async fn build_ec2_client_without_any_region_returns_region_not_resolved() {
        // Arrange
        let config = IngestConfig::default();

        // Act
        let result = build_ec2_client(&config).await;

        // Assert
        assert!(matches!(result, Err(IngestError::RegionNotResolved)));
    }
}
