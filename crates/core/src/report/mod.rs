//! Audit report data model (Milestone 4).
//!
//! Data types only: aggregation (`ReportBuilder`, issue #18), rendering and
//! export live in later tasks, and the written format contract in
//! `crates/core/docs/report.md` arrives with issue #24. The model validates
//! its own invariants, so it does not depend on those tasks to stay
//! consistent. Report output is data written to an `io::Write`, never routed
//! through `tracing`.

pub mod model;

pub use model::{
    AuditReport, IndeterminateCause, IndeterminateFinding, LayerCause, NotReachableFinding,
    ReachableFinding, ReportCounts, ReportScope, ReportSummary,
};
