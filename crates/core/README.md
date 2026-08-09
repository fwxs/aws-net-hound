# core

Graph schema and core contracts for aws-net-hound: Neo4j data model,
domain types, and shared logic. Library only, no binary entry point.

Consumed by the `audit-local` (local CLI) and `aws-deploy` (deployed
variant) binaries — all testable logic lives here so both binaries stay
thin.

## Build prerequisites

`aws-config`/`aws-sdk-ec2` pull in `aws-lc-sys` for TLS, which compiles a
native C library at build time. Building this crate therefore requires
`cmake` and a C compiler toolchain installed locally, in addition to Rust.
