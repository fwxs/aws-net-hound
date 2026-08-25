//! Classifies an AWS ingestion failure into an operator-facing message
//! (M3-T6). The ingest stage in [`crate::run`] surfaces raw
//! `aws-sdk-ec2`/`aws-sdk-sts` errors whose `Debug` output is a nested SDK
//! structure mentioning smithy operation names and a request ID — useless
//! to an auditor deciding whether their session expired, their IAM policy
//! is missing a permission, or the account genuinely has no VPCs.
//!
//! Classification matches on the SDK's typed error/error-code accessors
//! ([`ProvideErrorMetadata::code`]), never on substring-matching a rendered
//! message: error strings change between SDK minor versions and a
//! substring match fails silently. The rendered [`AwsFailure`] message
//! never carries a request ID, account ID, ARN, or raw SDK payload — those
//! belong behind `tracing::debug!` at the call site, not in the operator
//! sentence.

use aws_credential_types::provider::error::CredentialsError;
use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::result::SdkError;

/// An AWS ingestion failure classified into an operator-actionable class.
///
/// Each variant's message is written for the operator, not the developer:
/// it names what went wrong and what to do next. Every variant preserves
/// the original SDK error as [`std::error::Error::source`] — never printed
/// at operator-facing level (the `Display` impl this derive generates
/// never includes it), but available to `tracing::debug!(error = ?failure,
/// ..)` at the call site or to whoever files a support case with the
/// request ID.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AwsFailure {
    /// The configured AWS profile does not exist.
    #[error("AWS profile {profile:?} not found — check ~/.aws/config and ~/.aws/credentials")]
    ProfileNotFound {
        /// The profile name that could not be resolved.
        profile: String,
        /// The original credentials-resolution error, kept for `debug!`
        /// diagnosis only — never rendered in the operator-facing message.
        #[source]
        source: anyhow::Error,
    },

    /// Credentials were valid at some point but have since expired (an SSO
    /// or STS session that timed out).
    #[error("AWS credentials expired — refresh your SSO session (e.g. `aws sso login`) and retry")]
    ExpiredCredentials {
        /// The original SDK error, kept for `debug!` diagnosis only.
        #[source]
        source: anyhow::Error,
    },

    /// The caller's IAM identity lacks the permission required for the
    /// failing operation.
    #[error(
        "access denied calling {operation} — the caller's IAM identity needs the \
         {iam_action} permission"
    )]
    AccessDenied {
        /// The failing `Describe*`/API operation name.
        operation: &'static str,
        /// The IAM action required for `operation`, e.g. `"ec2:DescribeSecurityGroups"`.
        iam_action: &'static str,
        /// The original SDK error, kept for `debug!` diagnosis only.
        #[source]
        source: anyhow::Error,
    },

    /// The request was throttled and the client's retry policy was
    /// exhausted.
    #[error(
        "AWS request throttled after retries were exhausted — retry later or reduce concurrency"
    )]
    Throttled {
        /// The original SDK error, kept for `debug!` diagnosis only.
        #[source]
        source: anyhow::Error,
    },

    /// An AWS failure that doesn't fit any of the above classes. The
    /// original error is preserved as `source` and not paraphrased.
    #[error("unclassified AWS ingestion failure")]
    Other {
        /// The original error, untranslated.
        #[source]
        source: anyhow::Error,
    },
}

/// Maps a failing `Describe*` operation name to the read-only IAM action it
/// requires. Mirrors the five collectors in
/// `aws_net_hound_core::ingest::collect` plus the STS call
/// `aws_net_hound_core::ingest::aws_client::resolve_account_id` makes.
fn iam_action_for(operation: &'static str) -> &'static str {
    match operation {
        "DescribeSecurityGroups" => "ec2:DescribeSecurityGroups",
        "DescribeNetworkAcls" => "ec2:DescribeNetworkAcls",
        "DescribeRouteTables" => "ec2:DescribeRouteTables",
        "DescribeNetworkInterfaces" => "ec2:DescribeNetworkInterfaces",
        "DescribeVpcPeeringConnections" => "ec2:DescribeVpcPeeringConnections",
        "GetCallerIdentity" => "sts:GetCallerIdentity",
        _ => "the required EC2 read permission",
    }
}

/// The class an ingestion failure was recognized as, before the original
/// error is attached as its `source`. Kept separate from [`AwsFailure`] so
/// classification can borrow from `error`'s chain and only take ownership
/// of `error` itself once, after a match is found — seeing which class
/// matched never requires consuming the error being classified.
enum Class {
    ProfileNotFound {
        profile: String,
    },
    ExpiredCredentials,
    AccessDenied {
        operation: &'static str,
        iam_action: &'static str,
    },
    Throttled,
}

impl Class {
    fn into_failure(self, source: anyhow::Error) -> AwsFailure {
        match self {
            Class::ProfileNotFound { profile } => AwsFailure::ProfileNotFound { profile, source },
            Class::ExpiredCredentials => AwsFailure::ExpiredCredentials { source },
            Class::AccessDenied {
                operation,
                iam_action,
            } => AwsFailure::AccessDenied {
                operation,
                iam_action,
                source,
            },
            Class::Throttled => AwsFailure::Throttled { source },
        }
    }
}

/// Classifies an AWS error code (as returned by the SDK's own
/// [`ProvideErrorMetadata::code`]) for the given failing `operation` into
/// a [`Class`], or `None` if the code isn't one of the classes this module
/// distinguishes.
fn classify_code(operation: &'static str, code: Option<&str>) -> Option<Class> {
    match code? {
        "ExpiredToken" | "RequestExpired" | "ExpiredTokenException" => {
            Some(Class::ExpiredCredentials)
        }
        "UnauthorizedOperation" | "AccessDenied" | "AccessDeniedException" | "AuthFailure" => {
            Some(Class::AccessDenied {
                operation,
                iam_action: iam_action_for(operation),
            })
        }
        "RequestLimitExceeded" | "Throttling" | "ThrottlingException" => Some(Class::Throttled),
        _ => None,
    }
}

/// Classifies a [`CredentialsError`] into a [`Class`], or `None` if it
/// isn't one of the classes this module distinguishes (e.g. a timeout or
/// an unhandled provider error falls through to [`AwsFailure::Other`] at
/// the call site).
fn classify_credentials_error(error: &CredentialsError, profile: Option<&str>) -> Option<Class> {
    match error {
        CredentialsError::CredentialsNotLoaded(_) | CredentialsError::InvalidConfiguration(_) => {
            Some(Class::ProfileNotFound {
                profile: profile.unwrap_or("default").to_string(),
            })
        }
        _ => None,
    }
}

/// Classifies an ingestion failure for the given failing `operation` (e.g.
/// `"DescribeSecurityGroups"`, `"GetCallerIdentity"`) into an operator-facing
/// [`AwsFailure`].
///
/// Walks `error`'s source chain looking, in order, for: a [`CredentialsError`]
/// (missing/misconfigured profile), an EC2/STS error code recognized by
/// [`classify_code`] (expired session, access denied, throttled). Anything
/// else falls through to [`AwsFailure::Other`]. `error` itself — the full
/// chain, not just the matched link — is always preserved as the returned
/// variant's `source`, so `RUST_LOG=debug` can still see the request ID and
/// raw SDK detail this module's `Display` output deliberately omits.
pub fn classify(operation: &'static str, error: anyhow::Error) -> AwsFailure {
    let profile = std::env::var("AWS_PROFILE").ok();

    let class = error.chain().find_map(|cause| {
        if let Some(credentials_error) = cause.downcast_ref::<CredentialsError>() {
            if let Some(class) = classify_credentials_error(credentials_error, profile.as_deref()) {
                return Some(class);
            }
        }
        if let Some(sdk_error) = cause.downcast_ref::<SdkError<
            aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError,
            HttpResponse,
        >>() {
            if let Some(class) = classify_code(operation, sdk_error.code()) {
                return Some(class);
            }
        }
        classify_describe_error(operation, cause)
    });

    match class {
        Some(class) => class.into_failure(error),
        None => AwsFailure::Other { source: error },
    }
}

/// Tries each of the five `Describe*` operation error types in turn,
/// matching only the one that corresponds to `operation` so a downcast
/// failure on the other four never masks a real classification.
fn classify_describe_error(
    operation: &'static str,
    cause: &(dyn std::error::Error + 'static),
) -> Option<Class> {
    use aws_sdk_ec2::operation::{
        describe_network_acls::DescribeNetworkAclsError,
        describe_network_interfaces::DescribeNetworkInterfacesError,
        describe_route_tables::DescribeRouteTablesError,
        describe_security_groups::DescribeSecurityGroupsError,
        describe_vpc_peering_connections::DescribeVpcPeeringConnectionsError,
    };

    match operation {
        "DescribeSecurityGroups" => cause
            .downcast_ref::<SdkError<DescribeSecurityGroupsError, HttpResponse>>()
            .and_then(|error| classify_code(operation, error.code())),
        "DescribeNetworkAcls" => cause
            .downcast_ref::<SdkError<DescribeNetworkAclsError, HttpResponse>>()
            .and_then(|error| classify_code(operation, error.code())),
        "DescribeRouteTables" => cause
            .downcast_ref::<SdkError<DescribeRouteTablesError, HttpResponse>>()
            .and_then(|error| classify_code(operation, error.code())),
        "DescribeNetworkInterfaces" => cause
            .downcast_ref::<SdkError<DescribeNetworkInterfacesError, HttpResponse>>()
            .and_then(|error| classify_code(operation, error.code())),
        "DescribeVpcPeeringConnections" => cause
            .downcast_ref::<SdkError<DescribeVpcPeeringConnectionsError, HttpResponse>>()
            .and_then(|error| classify_code(operation, error.code())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use aws_credential_types::provider::error::CredentialsError;
    use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;
    use aws_smithy_types::body::SdkBody;
    use pretty_assertions::assert_eq;

    use super::*;

    /// A placeholder [`HttpResponse`] for tests that only exercise error
    /// classification, which never inspects the response itself.
    fn empty_response(status: u16) -> HttpResponse {
        let Ok(status) = status.try_into() else {
            panic!("{status} is not a valid HTTP status code");
        };
        HttpResponse::new(status, SdkBody::empty())
    }

    #[test]
    fn classify_missing_profile_error_returns_profile_not_found() {
        // Arrange
        let credentials_error = CredentialsError::not_loaded("no profile named 'staging'");
        let error = anyhow::Error::new(credentials_error);

        // Act
        let failure = classify("GetCallerIdentity", error);

        // Assert
        assert!(matches!(failure, AwsFailure::ProfileNotFound { .. }));
    }

    #[test]
    fn classify_expired_token_error_returns_expired_credentials() {
        // Arrange
        let sts_error = GetCallerIdentityError::generic(
            aws_smithy_types::error::ErrorMetadata::builder()
                .code("ExpiredTokenException")
                .message("token expired")
                .build(),
        );
        let sdk_error: SdkError<GetCallerIdentityError, HttpResponse> =
            SdkError::service_error(sts_error, empty_response(400));
        let error = anyhow::Error::new(sdk_error);

        // Act
        let failure = classify("GetCallerIdentity", error);

        // Assert
        assert!(matches!(failure, AwsFailure::ExpiredCredentials { .. }));
    }

    #[test]
    fn classify_access_denied_on_describe_security_groups_names_required_iam_action() {
        // Arrange
        let ec2_error =
            aws_sdk_ec2::operation::describe_security_groups::DescribeSecurityGroupsError::generic(
                aws_smithy_types::error::ErrorMetadata::builder()
                    .code("UnauthorizedOperation")
                    .message("not authorized")
                    .build(),
            );
        let sdk_error: SdkError<_, HttpResponse> =
            SdkError::service_error(ec2_error, empty_response(403));
        let error = anyhow::Error::new(sdk_error);

        // Act
        let failure = classify("DescribeSecurityGroups", error);

        // Assert
        match failure {
            AwsFailure::AccessDenied {
                operation,
                iam_action,
                source,
            } => {
                assert_eq!(operation, "DescribeSecurityGroups");
                assert_eq!(iam_action, "ec2:DescribeSecurityGroups");
                assert!(
                    source
                        .downcast_ref::<SdkError<
                            aws_sdk_ec2::operation::describe_security_groups::DescribeSecurityGroupsError,
                            HttpResponse,
                        >>()
                        .is_some(),
                    "classified failures must keep the original SDK error as source for debug diagnosis"
                );
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[test]
    fn classify_throttling_error_returns_throttled() {
        // Arrange
        let ec2_error =
            aws_sdk_ec2::operation::describe_route_tables::DescribeRouteTablesError::generic(
                aws_smithy_types::error::ErrorMetadata::builder()
                    .code("RequestLimitExceeded")
                    .build(),
            );
        let sdk_error: SdkError<_, HttpResponse> =
            SdkError::service_error(ec2_error, empty_response(503));
        let error = anyhow::Error::new(sdk_error);

        // Act
        let failure = classify("DescribeRouteTables", error);

        // Assert
        assert!(matches!(failure, AwsFailure::Throttled { .. }));
    }

    #[test]
    fn classify_unknown_service_error_returns_other_preserving_source() {
        // Arrange
        let ec2_error =
            aws_sdk_ec2::operation::describe_network_acls::DescribeNetworkAclsError::generic(
                aws_smithy_types::error::ErrorMetadata::builder()
                    .code("InternalError")
                    .build(),
            );
        let sdk_error: SdkError<_, HttpResponse> =
            SdkError::service_error(ec2_error, empty_response(500));
        let error = anyhow::Error::new(sdk_error);

        // Act
        let failure = classify("DescribeNetworkAcls", error);

        // Assert
        let AwsFailure::Other { source } = failure else {
            panic!("expected Other, got a classified variant");
        };
        assert!(source
            .downcast_ref::<SdkError<
                aws_sdk_ec2::operation::describe_network_acls::DescribeNetworkAclsError,
                HttpResponse,
            >>()
            .is_some());
    }

    #[test]
    fn operator_message_does_not_contain_request_id() {
        // Arrange
        let ec2_error =
            aws_sdk_ec2::operation::describe_security_groups::DescribeSecurityGroupsError::generic(
                aws_smithy_types::error::ErrorMetadata::builder()
                    .code("UnauthorizedOperation")
                    .message("not authorized")
                    .custom("request_id", "req-1234-secret")
                    .build(),
            );
        let sdk_error: SdkError<_, HttpResponse> =
            SdkError::service_error(ec2_error, empty_response(403));
        let error = anyhow::Error::new(sdk_error);

        // Act
        let failure = classify("DescribeSecurityGroups", error);
        let rendered = failure.to_string();

        // Assert
        assert!(!rendered.contains("req-1234-secret"));
    }
}
