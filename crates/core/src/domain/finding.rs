//! Reachability finding domain types, emitted by the Milestone 2 evaluator
//! and rendered by Milestone 4. Rendering (turning `path_evidence` into
//! human-readable text) is out of scope here — this module only carries
//! structured evidence.

use serde::{Deserialize, Serialize};

/// Severity of a reachability finding.
///
/// `Ord` is derived from declaration order — `Low < Medium < High <
/// Critical` — and pinned by
/// `tests::severity_ord_ranks_in_declared_order`. A new variant must be
/// inserted at its intended rank, not appended, or that test catches the
/// inversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// The node types a reachability path can hop through, mirroring the node
/// kinds in `schema.md`. Serialized values match the graph node labels
/// exactly (`ENI`, `SecurityGroup`, `NetworkACL`, ...), not
/// `snake_case`, so a `Hop.node_kind` compares directly against a Cypher
/// label string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    #[serde(rename = "ENI")]
    Eni,
    SecurityGroup,
    #[serde(rename = "NetworkACL")]
    NetworkAcl,
    Subnet,
    #[serde(rename = "VPC")]
    Vpc,
    RouteTable,
    RegulatedBoundary,
}

/// A single hop traversed while computing a reachability finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    /// The unique key (e.g. `sg-0example`) of the node at this hop.
    pub node_id: String,
    /// The node type at this hop.
    pub node_kind: NodeKind,
}

/// The structured path an evaluator traversed to produce a
/// `ReachabilityFinding`. Kept as structured hops, not a pre-rendered
/// string, so Milestone 4 can render it in whatever form (table, graph,
/// text) it needs without re-deriving the path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathEvidence {
    /// Hops traversed, in traversal order (source first, destination last).
    pub hops: Vec<Hop>,
}

/// A computed reachability finding: a source was found to reach a
/// regulated boundary, with the evidentiary path and its severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityFinding {
    /// UTC timestamp, ISO-8601 (RFC 3339), of when this finding was
    /// computed.
    pub computed_at: String,
    /// Unique key of the source node the reachability check started from
    /// (e.g. an `ENI` id).
    pub source: String,
    /// `RegulatedBoundary.id` this finding correlates against — matched by
    /// key, not graph traversal, per `schema.md`.
    pub destination_boundary: String,
    /// Structured evidence of the path that produced this finding.
    pub path_evidence: PathEvidence,
    /// How severe this finding is.
    pub severity: Severity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn reachability_finding_serializes_structured_path_evidence() {
        // Arrange
        let finding = ReachabilityFinding {
            computed_at: "2026-08-08T00:00:00Z".to_string(),
            source: "eni-0example".to_string(),
            destination_boundary: "boundary-pci-prod".to_string(),
            path_evidence: PathEvidence {
                hops: vec![
                    Hop {
                        node_id: "eni-0example".to_string(),
                        node_kind: NodeKind::Eni,
                    },
                    Hop {
                        node_id: "sg-0example".to_string(),
                        node_kind: NodeKind::SecurityGroup,
                    },
                ],
            },
            severity: Severity::High,
        };

        // Act
        let serialized = serde_norway::to_string(&finding)
            .unwrap_or_else(|error| panic!("failed to serialize ReachabilityFinding: {error}"));
        let roundtripped: ReachabilityFinding = serde_norway::from_str(&serialized)
            .unwrap_or_else(|error| panic!("failed to deserialize ReachabilityFinding: {error}"));

        // Assert
        assert_eq!(roundtripped, finding);
    }

    #[test]
    fn severity_ord_ranks_in_declared_order() {
        // Arrange
        let ascending = [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let mut shuffled = [
            Severity::Critical,
            Severity::Low,
            Severity::High,
            Severity::Medium,
        ];

        // Act
        shuffled.sort();

        // Assert
        assert_eq!(shuffled, ascending);
    }

    #[test]
    fn node_kind_serializes_using_graph_labels() {
        // Arrange
        let kinds = [
            (NodeKind::Eni, "ENI"),
            (NodeKind::NetworkAcl, "NetworkACL"),
            (NodeKind::Vpc, "VPC"),
        ];

        // Act & Assert
        for (kind, label) in kinds {
            let serialized = serde_norway::to_string(&kind)
                .unwrap_or_else(|error| panic!("failed to serialize NodeKind: {error}"));
            assert_eq!(serialized.trim(), label);
        }
    }
}
