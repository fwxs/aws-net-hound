//! Domain types: pure Rust structs and enums with no Neo4j driver
//! dependency. Field names mirror the edge/node properties in
//! `crates/core/docs/schema.md`, which is authoritative.

pub mod finding;
pub mod rule;

pub use finding::{ReachabilityFinding, Severity};
pub use rule::{Action, Direction, NaclRule, PortRange, RuleError, RuleTarget, SgRule};
