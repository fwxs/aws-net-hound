//! Audit report data model (Milestone 4).
//!
//! Data types only: aggregation, rendering and export live in later tasks.
//! Report output is data written to an `io::Write`, never routed through
//! `tracing`.

pub mod model;

pub use model::{
    AuditReport, IndeterminateCause, IndeterminateFinding, NotReachableFinding, ReachableFinding,
    ReportCounts, ReportScope, ReportSummary,
};
