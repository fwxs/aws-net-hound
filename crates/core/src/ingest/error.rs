//! Error types for `crate::ingest`.

use thiserror::Error;

/// Errors that can occur while building an AWS client for ingestion.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IngestError {
    /// No AWS region was available from [`crate::ingest::IngestConfig::region`],
    /// `AWS_REGION`, `AWS_DEFAULT_REGION`, or a profile default. A region is
    /// never guessed or defaulted — see [`crate::ingest::aws_client::build_ec2_client`].
    #[error(
        "no AWS region resolved: set `IngestConfig::region`, `AWS_REGION`/`AWS_DEFAULT_REGION`, \
         or a profile default region"
    )]
    RegionNotResolved,
}
