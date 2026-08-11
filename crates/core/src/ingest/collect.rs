//! Paginated collectors for the five EC2 `Describe*` APIs Milestone 1
//! ingests: security groups, network ACLs, route tables, network
//! interfaces, and VPC peering connections.
//!
//! Every EC2 `Describe*` call returns at most one page. A first-page-only
//! implementation would produce a graph that is structurally valid,
//! queryable, and wrong by omission, so every collector here drains all
//! pages via the SDK's generated paginator
//! ([`into_paginator()`](aws_sdk_ec2::operation::describe_security_groups::builders::DescribeSecurityGroupsFluentBuilder::into_paginator))
//! rather than a hand-written `next_token` loop, and returns the union of
//! every page as an owned `Vec` of the SDK's own type.
//!
//! These functions return the raw SDK types deliberately: mapping to
//! domain types is M1-T3's job, and keeping the two separable is what
//! makes both testable without the other. No filters are applied — scoping
//! is single-account/single-region by construction, via the client's
//! region and credentials.

use aws_sdk_ec2::Client;
use aws_smithy_async::future::pagination_stream::PaginationStream;
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::result::SdkError;
use tracing::{debug, info};

use crate::error::IngestError;

/// Drains every page of a paginated `Describe*` response, extracting each
/// page's items with `extract_items` and accumulating them in arrival
/// order.
///
/// Shared by every collector in this module so the pagination, logging,
/// and error-mapping behaviour cannot diverge between the five `Describe*`
/// APIs. Never logs a page's contents — only its item count — since ENI
/// descriptions and tags routinely carry hostnames and owner names.
async fn drain_pages<Output, Item, Error>(
    operation: &'static str,
    mut pages: PaginationStream<Result<Output, SdkError<Error, HttpResponse>>>,
    extract_items: impl Fn(Output) -> Vec<Item>,
) -> Result<Vec<Item>, IngestError>
where
    Error: std::error::Error + Send + Sync + 'static,
{
    let mut items = Vec::new();
    while let Some(page) = pages.next().await {
        let output = page.map_err(|source| IngestError::Describe {
            operation,
            source: Box::new(source),
        })?;
        let page_items = extract_items(output);
        debug!(operation, page_items = page_items.len(), "received page");
        items.extend(page_items);
    }
    info!(operation, total_items = items.len(), "collected all pages");
    Ok(items)
}

/// Drains all pages of `DescribeSecurityGroups`, returning every security
/// group in the account/region the client is scoped to.
pub async fn collect_security_groups(
    client: &Client,
) -> Result<Vec<aws_sdk_ec2::types::SecurityGroup>, IngestError> {
    drain_pages(
        "DescribeSecurityGroups",
        client.describe_security_groups().into_paginator().send(),
        |output| output.security_groups.unwrap_or_default(),
    )
    .await
}

/// Drains all pages of `DescribeNetworkAcls`, returning every network ACL
/// in the account/region the client is scoped to.
pub async fn collect_network_acls(
    client: &Client,
) -> Result<Vec<aws_sdk_ec2::types::NetworkAcl>, IngestError> {
    drain_pages(
        "DescribeNetworkAcls",
        client.describe_network_acls().into_paginator().send(),
        |output| output.network_acls.unwrap_or_default(),
    )
    .await
}

/// Drains all pages of `DescribeRouteTables`, returning every route table
/// in the account/region the client is scoped to.
pub async fn collect_route_tables(
    client: &Client,
) -> Result<Vec<aws_sdk_ec2::types::RouteTable>, IngestError> {
    drain_pages(
        "DescribeRouteTables",
        client.describe_route_tables().into_paginator().send(),
        |output| output.route_tables.unwrap_or_default(),
    )
    .await
}

/// Drains all pages of `DescribeNetworkInterfaces`, returning every ENI in
/// the account/region the client is scoped to.
pub async fn collect_network_interfaces(
    client: &Client,
) -> Result<Vec<aws_sdk_ec2::types::NetworkInterface>, IngestError> {
    drain_pages(
        "DescribeNetworkInterfaces",
        client.describe_network_interfaces().into_paginator().send(),
        |output| output.network_interfaces.unwrap_or_default(),
    )
    .await
}

/// Drains all pages of `DescribeVpcPeeringConnections`, returning every
/// VPC peering connection in the account/region the client is scoped to.
pub async fn collect_vpc_peering_connections(
    client: &Client,
) -> Result<Vec<aws_sdk_ec2::types::VpcPeeringConnection>, IngestError> {
    drain_pages(
        "DescribeVpcPeeringConnections",
        client
            .describe_vpc_peering_connections()
            .into_paginator()
            .send(),
        |output| output.vpc_peering_connections.unwrap_or_default(),
    )
    .await
}
