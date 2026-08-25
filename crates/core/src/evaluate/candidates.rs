//! Assembles [`PathCandidate`]s from the graph for a [`RegulatedBoundary`]
//! (M3-T5), so an [`crate::ports::Evaluator`] has something to judge.
//!
//! Kept deliberately narrow: a destination ENI is any `ENI` whose `vpc_id`
//! is in [`BoundarySelectors::vpc_ids`] — the only selector with real graph
//! data today (see the module-level gap note on `cidrs`/`tags` below). A
//! source ENI is every other `ENI` reachable to a destination's subnet via
//! `USES_ROUTE_TABLE` -> `ROUTES_TO` -> a shared `VPC` node (the local-route
//! shape `schema.md` describes); cross-VPC or unresolved routes yield
//! `route_exists = false` rather than a guess.
//!
//! `cidrs` and `tags` selectors are accepted and threaded through so a
//! caller can warn when they're set, but they match nothing yet:
//! `Subnet.cidr_block`/`VPC.cidr_block` stay empty strings until a
//! `DescribeSubnets`/`DescribeVpcs` collector exists (`schema.md`'s `Subnet`
//! node note), and no tag data is ingested into the graph at all.

use std::collections::HashMap;
use std::net::IpAddr;

use neo4rs::{query, Graph, Row};

use crate::domain::rule::{Action, Direction, NaclRule, PortRange, RuleTarget, SgRule};
use crate::error::CandidateAssemblyError;
use crate::evaluate::path::{EndpointCandidate, PathCandidate};
use crate::evaluate::{Protocol, Traffic};

/// Which of a [`crate::config`]-shaped boundary's selector lists to match
/// destination ENIs against. Borrowed rather than owned so a caller with a
/// `&ValidatedConfig` doesn't need to clone its `Vec<String>`s.
#[derive(Debug, Clone, Copy)]
pub struct BoundarySelectors<'a> {
    pub vpc_ids: &'a [String],
    pub cidrs: &'a [String],
    pub tags: &'a [String],
}

/// One ENI's full endpoint shape as read off the graph, before it's paired
/// into a [`PathCandidate`].
struct EniNode {
    id: String,
    vpc_id: String,
    subnet_id: String,
    private_ip: String,
    security_group_ids: Vec<String>,
    egress_rules: Vec<SgRule>,
    ingress_rules: Vec<SgRule>,
    nacl_rules: Vec<NaclRule>,
    route_table_id: Option<String>,
}

impl EniNode {
    fn source_endpoint(&self) -> EndpointCandidate {
        EndpointCandidate {
            eni_id: self.id.clone(),
            peer_security_group_ids: self.security_group_ids.clone(),
            security_group_rules: self.egress_rules.clone(),
            subnet_id: self.subnet_id.clone(),
            nacl_rules: self.nacl_rules.clone(),
        }
    }

    fn destination_endpoint(&self) -> EndpointCandidate {
        EndpointCandidate {
            eni_id: self.id.clone(),
            peer_security_group_ids: self.security_group_ids.clone(),
            security_group_rules: self.ingress_rules.clone(),
            subnet_id: self.subnet_id.clone(),
            nacl_rules: self.nacl_rules.clone(),
        }
    }
}

const ENI_QUERY: &str = "\
MATCH (eni:ENI)
OPTIONAL MATCH (eni)-[:IN_SUBNET]->(subnet:Subnet)
OPTIONAL MATCH (subnet)-[:USES_ROUTE_TABLE]->(rt:RouteTable)
OPTIONAL MATCH (subnet)-[:PROTECTED_BY]->(acl:NetworkACL)
OPTIONAL MATCH (acl)-[nacl_rule:HAS_RULE]->(acl)
OPTIONAL MATCH (eni)-[:HAS_SG]->(sg:SecurityGroup)
OPTIONAL MATCH (sg)-[egress:ALLOWS_EGRESS]->()
OPTIONAL MATCH (sg)-[ingress:ALLOWS_INGRESS]->()
RETURN
    eni.id AS eni_id,
    eni.vpc_id AS vpc_id,
    eni.subnet_id AS subnet_id,
    eni.private_ip AS private_ip,
    rt.id AS route_table_id,
    collect(DISTINCT sg.id) AS security_group_ids,
    collect(DISTINCT egress) AS egress_rules,
    collect(DISTINCT ingress) AS ingress_rules,
    collect(DISTINCT nacl_rule) AS nacl_rules";

/// Which `VPC` a `RouteTable` locally routes to, via a resolved `ROUTES_TO`
/// edge — used to decide `route_exists` between two ENIs' route tables.
const ROUTE_TABLE_TARGETS_QUERY: &str = "\
MATCH (rt:RouteTable)-[edge:ROUTES_TO {resolved: true}]->(vpc:VPC)
RETURN rt.id AS route_table_id, collect(DISTINCT vpc.id) AS target_vpc_ids";

/// Assembles one [`PathCandidate`] per (source ENI, destination ENI) pair,
/// where the destination is any ENI matched by `selectors` against
/// `boundary_id`, and the source is every other ENI in the graph.
///
/// `Traffic` is fixed per candidate to [`Protocol::All`] with no port — the
/// broadest possible check, matching an audit tool surfacing worst-case
/// reachability rather than one flow at a time. A later milestone may allow
/// narrowing this to config-specified traffic. A source ENI whose
/// `private_ip` fails to parse as an [`IpAddr`] is skipped, not fatal to the
/// whole assembly.
pub async fn assemble_candidates(
    graph: &Graph,
    boundary_id: &str,
    selectors: BoundarySelectors<'_>,
) -> Result<Vec<PathCandidate>, CandidateAssemblyError> {
    let enis = fetch_enis(graph).await?;
    let route_targets = fetch_route_table_targets(graph).await?;

    let vpc_match: std::collections::HashSet<&str> =
        selectors.vpc_ids.iter().map(String::as_str).collect();

    let (destinations, sources): (Vec<&EniNode>, Vec<&EniNode>) = enis
        .iter()
        .partition(|eni| vpc_match.contains(eni.vpc_id.as_str()));

    let mut candidates = Vec::new();
    for destination in &destinations {
        for source in &sources {
            let Ok(peer_address) = source.private_ip.parse::<IpAddr>() else {
                continue;
            };

            let route_exists = route_exists(source, destination, &route_targets);

            candidates.push(PathCandidate {
                source: source.source_endpoint(),
                destination: destination.destination_endpoint(),
                route_exists,
                traffic: Traffic {
                    protocol: Protocol::All,
                    port: None,
                    peer_address,
                },
                destination_boundary: boundary_id.to_string(),
            });
        }
    }

    Ok(candidates)
}

fn route_exists(
    source: &EniNode,
    destination: &EniNode,
    route_targets: &HashMap<String, Vec<String>>,
) -> bool {
    if source.subnet_id == destination.subnet_id {
        return true;
    }
    let (Some(source_rt), Some(destination_rt)) =
        (&source.route_table_id, &destination.route_table_id)
    else {
        return false;
    };
    let Some(source_targets) = route_targets.get(source_rt) else {
        return false;
    };
    let Some(destination_targets) = route_targets.get(destination_rt) else {
        return false;
    };
    source_targets
        .iter()
        .any(|vpc_id| destination_targets.contains(vpc_id) || *vpc_id == destination.vpc_id)
        || source_targets.contains(&destination.vpc_id)
}

async fn fetch_route_table_targets(
    graph: &Graph,
) -> Result<HashMap<String, Vec<String>>, CandidateAssemblyError> {
    let mut stream = graph
        .execute(query(ROUTE_TABLE_TARGETS_QUERY))
        .await
        .map_err(|source| CandidateAssemblyError::Query { source })?;

    let mut targets = HashMap::new();
    while let Some(row) = stream
        .next()
        .await
        .map_err(|source| CandidateAssemblyError::Query { source })?
    {
        let route_table_id: String = row
            .get("route_table_id")
            .map_err(|source| CandidateAssemblyError::Deserialize { source })?;
        let target_vpc_ids: Vec<String> = row
            .get("target_vpc_ids")
            .map_err(|source| CandidateAssemblyError::Deserialize { source })?;
        targets.insert(route_table_id, target_vpc_ids);
    }
    Ok(targets)
}

async fn fetch_enis(graph: &Graph) -> Result<Vec<EniNode>, CandidateAssemblyError> {
    let mut stream = graph
        .execute(query(ENI_QUERY))
        .await
        .map_err(|source| CandidateAssemblyError::Query { source })?;

    let mut enis = Vec::new();
    while let Some(row) = stream
        .next()
        .await
        .map_err(|source| CandidateAssemblyError::Query { source })?
    {
        enis.push(eni_from_row(&row)?);
    }
    Ok(enis)
}

fn eni_from_row(row: &Row) -> Result<EniNode, CandidateAssemblyError> {
    let get_string = |field: &'static str| -> Result<String, CandidateAssemblyError> {
        row.get(field)
            .map_err(|source| CandidateAssemblyError::Deserialize { source })
    };
    let get_opt_string = |field: &'static str| -> Option<String> { row.get(field).ok() };

    let security_group_ids: Vec<String> = row
        .get("security_group_ids")
        .map_err(|source| CandidateAssemblyError::Deserialize { source })?;
    let egress_rules = sg_rules_from_row(row, "egress_rules")?;
    let ingress_rules = sg_rules_from_row(row, "ingress_rules")?;
    let mut nacl_rules = nacl_rules_from_row(row)?;
    nacl_rules.sort_by_key(|rule| rule.rule_number);

    Ok(EniNode {
        id: get_string("eni_id")?,
        vpc_id: get_string("vpc_id")?,
        subnet_id: get_string("subnet_id")?,
        private_ip: get_string("private_ip")?,
        security_group_ids,
        egress_rules,
        ingress_rules,
        nacl_rules,
        route_table_id: get_opt_string("route_table_id"),
    })
}

/// One `ALLOWS_EGRESS`/`ALLOWS_INGRESS` edge's properties as returned by
/// `collect(DISTINCT edge)` — a list of property maps, `null` entries
/// dropped since `OPTIONAL MATCH` on a security-group-less ENI yields none.
fn sg_rules_from_row(
    row: &Row,
    field: &'static str,
) -> Result<Vec<SgRule>, CandidateAssemblyError> {
    let raw: Vec<HashMap<String, neo4rs::BoltType>> = row
        .get(field)
        .map_err(|source| CandidateAssemblyError::Deserialize { source })?;

    raw.into_iter()
        .filter(|props| !props.is_empty())
        .map(sg_rule_from_props)
        .collect()
}

fn sg_rule_from_props(
    props: HashMap<String, neo4rs::BoltType>,
) -> Result<SgRule, CandidateAssemblyError> {
    let protocol = bolt_string(&props, "protocol")?;
    let from_port = bolt_opt_u16(&props, "from_port");
    let to_port = bolt_opt_u16(&props, "to_port");
    let port_range =
        match (from_port, to_port) {
            (Some(from), Some(to)) => Some(PortRange::new(from, to).map_err(|_| {
                CandidateAssemblyError::MalformedRow {
                    field: "port_range",
                }
            })?),
            _ => None,
        };
    let target_kind = bolt_string(&props, "target_kind")?;
    let target = match target_kind.as_str() {
        "cidr" => RuleTarget::Cidr {
            cidr: bolt_string(&props, "cidr")?,
        },
        "security_group_ref" => RuleTarget::SecurityGroupRef {
            security_group_id: bolt_string(&props, "target_security_group_id")?,
        },
        _ => {
            return Err(CandidateAssemblyError::MalformedRow {
                field: "target_kind",
            })
        }
    };
    let resolved = matches!(
        props.get("resolved"),
        Some(neo4rs::BoltType::Boolean(neo4rs::BoltBoolean {
            value: true
        }))
    );

    Ok(SgRule {
        // `direction` selects the edge type, not a persisted property, so
        // it can't be read back — see `schema.md`'s struct-to-property
        // crosswalk. Both `source_endpoint`/`destination_endpoint` only use
        // whichever of `egress_rules`/`ingress_rules` matches the direction
        // they need, so the value here is never consulted.
        direction: Direction::Egress,
        protocol,
        port_range,
        target,
        resolved,
    })
}

fn nacl_rules_from_row(row: &Row) -> Result<Vec<NaclRule>, CandidateAssemblyError> {
    let raw: Vec<HashMap<String, neo4rs::BoltType>> = row
        .get("nacl_rules")
        .map_err(|source| CandidateAssemblyError::Deserialize { source })?;

    raw.into_iter()
        .filter(|props| !props.is_empty())
        .map(nacl_rule_from_props)
        .collect()
}

fn nacl_rule_from_props(
    props: HashMap<String, neo4rs::BoltType>,
) -> Result<NaclRule, CandidateAssemblyError> {
    let rule_number = bolt_i64(&props, "rule_number")? as u16;
    let direction = match bolt_string(&props, "direction")?.as_str() {
        "ingress" => Direction::Ingress,
        "egress" => Direction::Egress,
        _ => return Err(CandidateAssemblyError::MalformedRow { field: "direction" }),
    };
    let protocol = bolt_string(&props, "protocol")?;
    let from_port = bolt_opt_u16(&props, "from_port");
    let to_port = bolt_opt_u16(&props, "to_port");
    let port_range =
        match (from_port, to_port) {
            (Some(from), Some(to)) => Some(PortRange::new(from, to).map_err(|_| {
                CandidateAssemblyError::MalformedRow {
                    field: "port_range",
                }
            })?),
            _ => None,
        };
    let cidr = bolt_string(&props, "cidr")?;
    let action = match bolt_string(&props, "action")?.as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        _ => return Err(CandidateAssemblyError::MalformedRow { field: "action" }),
    };

    Ok(NaclRule {
        rule_number,
        direction,
        protocol,
        port_range,
        cidr,
        action,
    })
}

fn bolt_string(
    props: &HashMap<String, neo4rs::BoltType>,
    field: &'static str,
) -> Result<String, CandidateAssemblyError> {
    match props.get(field) {
        Some(neo4rs::BoltType::String(value)) => Ok(value.value.clone()),
        _ => Err(CandidateAssemblyError::MalformedRow { field }),
    }
}

fn bolt_i64(
    props: &HashMap<String, neo4rs::BoltType>,
    field: &'static str,
) -> Result<i64, CandidateAssemblyError> {
    match props.get(field) {
        Some(neo4rs::BoltType::Integer(value)) => Ok(value.value),
        _ => Err(CandidateAssemblyError::MalformedRow { field }),
    }
}

fn bolt_opt_u16(props: &HashMap<String, neo4rs::BoltType>, field: &'static str) -> Option<u16> {
    match props.get(field) {
        Some(neo4rs::BoltType::Integer(value)) => u16::try_from(value.value).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap as StdHashMap;

    use super::*;

    fn eni(id: &str, vpc_id: &str, subnet_id: &str, route_table_id: Option<&str>) -> EniNode {
        EniNode {
            id: id.to_string(),
            vpc_id: vpc_id.to_string(),
            subnet_id: subnet_id.to_string(),
            private_ip: "10.0.0.1".to_string(),
            security_group_ids: Vec::new(),
            egress_rules: Vec::new(),
            ingress_rules: Vec::new(),
            nacl_rules: Vec::new(),
            route_table_id: route_table_id.map(str::to_string),
        }
    }

    #[test]
    fn route_exists_same_subnet_is_always_true() {
        // Arrange
        let source = eni("eni-a", "vpc-1", "subnet-1", None);
        let destination = eni("eni-b", "vpc-1", "subnet-1", None);
        let targets = StdHashMap::new();

        // Act
        let exists = route_exists(&source, &destination, &targets);

        // Assert
        assert!(exists);
    }

    #[test]
    fn route_exists_no_route_table_returns_false() {
        // Arrange
        let source = eni("eni-a", "vpc-1", "subnet-1", None);
        let destination = eni("eni-b", "vpc-1", "subnet-2", None);
        let targets = StdHashMap::new();

        // Act
        let exists = route_exists(&source, &destination, &targets);

        // Assert
        assert!(!exists);
    }

    #[test]
    fn route_exists_shared_local_vpc_target_returns_true() {
        // Arrange
        let source = eni("eni-a", "vpc-1", "subnet-1", Some("rtb-a"));
        let destination = eni("eni-b", "vpc-1", "subnet-2", Some("rtb-b"));
        let mut targets = StdHashMap::new();
        targets.insert("rtb-a".to_string(), vec!["vpc-1".to_string()]);
        targets.insert("rtb-b".to_string(), vec!["vpc-1".to_string()]);

        // Act
        let exists = route_exists(&source, &destination, &targets);

        // Assert
        assert!(exists);
    }

    #[test]
    fn route_exists_unresolved_route_returns_false() {
        // Arrange
        let source = eni("eni-a", "vpc-1", "subnet-1", Some("rtb-a"));
        let destination = eni("eni-b", "vpc-2", "subnet-2", Some("rtb-b"));
        let targets = StdHashMap::new();

        // Act
        let exists = route_exists(&source, &destination, &targets);

        // Assert
        assert!(!exists);
    }
}
