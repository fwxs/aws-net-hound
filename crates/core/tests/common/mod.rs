//! Shared test-only fixtures used by more than one integration test file:
//! an in-memory `GraphWriter` and `aws-smithy-mocks` EC2 client helpers.
//! Not itself a test binary — reached via `mod common;` from sibling files.

// Locking a freshly-constructed `Mutex` and unwrapping trivial constructors
// in test arrange steps is not the thing under test.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// This module is compiled separately per integration-test binary via
// `mod common;`; each binary only uses a subset of these helpers, so
// unused-per-binary items would otherwise trip `-D dead-code`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use aws_net_hound_core::domain::{NaclRule, SgRule};
use aws_net_hound_core::error::GraphWriteError;
use aws_net_hound_core::ports::{
    BoxFuture, EniRecord, GraphWriter, HasSgEdge, InSubnetEdge, NaclRuleBatch, NetworkAclRecord,
    ProtectedByEdge, RegulatedBoundaryRecord, RouteTableRecord, RoutesToEdge, SecurityGroupRecord,
    SgRuleBatch, SubnetRecord, UsesRouteTableEdge, VpcRecord,
};
use aws_sdk_ec2::config::retry::RetryConfig;
use aws_sdk_ec2::Client;
use aws_smithy_mocks::{mock_client, Rule, RuleMode};

/// A retry config with negligible backoff, so tests that trigger a retry
/// don't sleep for real backoff durations.
pub fn fast_retry_config() -> RetryConfig {
    RetryConfig::standard()
        .with_max_attempts(3)
        .with_initial_backoff(Duration::from_millis(1))
        .with_max_backoff(Duration::from_millis(5))
}

/// Builds a mock EC2 client serving `rules` and applies
/// [`fast_retry_config`] so retry-triggering tests stay fast.
pub fn mock_ec2_client(rules: &[&Rule]) -> Client {
    mock_client!(aws_sdk_ec2, RuleMode::MatchAny, rules, |conf| conf
        .retry_config(fast_retry_config()))
}

/// Minimal `GraphWriter` backed by `HashMap`s guarded by `std::sync::Mutex`.
/// Each upsert method inserts synchronously and returns an already-ready
/// future — there is no real I/O to await. `fail_writes` makes every upsert
/// return `Err` instead, for tests asserting on write-failure behavior.
#[derive(Default)]
pub struct InMemoryGraphWriter {
    fail_writes: bool,
    enis: Mutex<HashMap<String, EniRecord>>,
    security_groups: Mutex<HashMap<String, SecurityGroupRecord>>,
    network_acls: Mutex<HashMap<String, NetworkAclRecord>>,
    subnets: Mutex<HashMap<String, SubnetRecord>>,
    vpcs: Mutex<HashMap<String, VpcRecord>>,
    route_tables: Mutex<HashMap<String, RouteTableRecord>>,
    regulated_boundaries: Mutex<HashMap<String, RegulatedBoundaryRecord>>,
    has_sg_edges: Mutex<HashMap<(String, String), HasSgEdge>>,
    in_subnet_edges: Mutex<HashMap<(String, String), InSubnetEdge>>,
    protected_by_edges: Mutex<HashMap<(String, String), ProtectedByEdge>>,
    uses_route_table_edges: Mutex<HashMap<(String, String), UsesRouteTableEdge>>,
    routes_to_edges: Mutex<HashMap<(String, String), RoutesToEdge>>,
    egress_rules: Mutex<HashMap<String, Vec<SgRule>>>,
    ingress_rules: Mutex<HashMap<String, Vec<SgRule>>>,
    has_rules: Mutex<HashMap<String, Vec<NaclRule>>>,
}

impl InMemoryGraphWriter {
    /// Builds a writer whose every upsert method returns `Err` instead of
    /// writing, for tests asserting a run aborts on a write failure.
    pub fn failing() -> Self {
        Self {
            fail_writes: true,
            ..Self::default()
        }
    }

    /// Reads back a single upserted `ENI` by id, public-API surface for
    /// tests only (not part of `GraphWriter`).
    pub fn eni(&self, id: &str) -> Option<EniRecord> {
        self.enis.lock().unwrap().get(id).cloned()
    }

    /// Total node count across every node type, for asserting an upsert of
    /// "one of everything" landed.
    pub fn node_count(&self) -> usize {
        self.enis.lock().unwrap().len()
            + self.security_groups.lock().unwrap().len()
            + self.network_acls.lock().unwrap().len()
            + self.subnets.lock().unwrap().len()
            + self.vpcs.lock().unwrap().len()
            + self.route_tables.lock().unwrap().len()
            + self.regulated_boundaries.lock().unwrap().len()
    }

    /// Total topology-edge count across every edge type.
    pub fn edge_count(&self) -> usize {
        self.has_sg_edges.lock().unwrap().len()
            + self.in_subnet_edges.lock().unwrap().len()
            + self.protected_by_edges.lock().unwrap().len()
            + self.uses_route_table_edges.lock().unwrap().len()
            + self.routes_to_edges.lock().unwrap().len()
    }

    /// Total rule count (SG egress + SG ingress + NACL) across every batch.
    pub fn rule_count(&self) -> usize {
        self.egress_rules
            .lock()
            .unwrap()
            .values()
            .map(Vec::len)
            .sum::<usize>()
            + self
                .ingress_rules
                .lock()
                .unwrap()
                .values()
                .map(Vec::len)
                .sum::<usize>()
            + self
                .has_rules
                .lock()
                .unwrap()
                .values()
                .map(Vec::len)
                .sum::<usize>()
    }
}

fn write_failed() -> GraphWriteError {
    GraphWriteError::Write {
        source: "simulated write failure".into(),
    }
}

/// Inserts `records` into `store`, keyed by `key_fn`, MERGE-style (repeated
/// upserts of the same key overwrite in place rather than duplicate).
fn upsert<K, V>(store: &Mutex<HashMap<K, V>>, key_fn: impl Fn(&V) -> K, records: &[V])
where
    K: Eq + std::hash::Hash,
    V: Clone,
{
    let mut guard = store.lock().unwrap();
    for record in records {
        guard.insert(key_fn(record), record.clone());
    }
}

impl GraphWriter for InMemoryGraphWriter {
    fn upsert_enis(&self, enis: &[EniRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(&self.enis, |record| record.id.clone(), enis);
        Box::pin(async { Ok(()) })
    }

    fn upsert_security_groups(
        &self,
        security_groups: &[SecurityGroupRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(
            &self.security_groups,
            |record| record.id.clone(),
            security_groups,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_network_acls(
        &self,
        network_acls: &[NetworkAclRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(&self.network_acls, |record| record.id.clone(), network_acls);
        Box::pin(async { Ok(()) })
    }

    fn upsert_subnets(
        &self,
        subnets: &[SubnetRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(&self.subnets, |record| record.id.clone(), subnets);
        Box::pin(async { Ok(()) })
    }

    fn upsert_vpcs(&self, vpcs: &[VpcRecord]) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(&self.vpcs, |record| record.id.clone(), vpcs);
        Box::pin(async { Ok(()) })
    }

    fn upsert_route_tables(
        &self,
        route_tables: &[RouteTableRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(&self.route_tables, |record| record.id.clone(), route_tables);
        Box::pin(async { Ok(()) })
    }

    fn upsert_regulated_boundaries(
        &self,
        boundaries: &[RegulatedBoundaryRecord],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(
            &self.regulated_boundaries,
            |record| record.id.clone(),
            boundaries,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_has_sg_edges(
        &self,
        edges: &[HasSgEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(
            &self.has_sg_edges,
            |edge| (edge.eni_id.clone(), edge.security_group_id.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_in_subnet_edges(
        &self,
        edges: &[InSubnetEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(
            &self.in_subnet_edges,
            |edge| (edge.eni_id.clone(), edge.subnet_id.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_protected_by_edges(
        &self,
        edges: &[ProtectedByEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(
            &self.protected_by_edges,
            |edge| (edge.subnet_id.clone(), edge.network_acl_id.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_uses_route_table_edges(
        &self,
        edges: &[UsesRouteTableEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(
            &self.uses_route_table_edges,
            |edge| (edge.subnet_id.clone(), edge.route_table_id.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_routes_to_edges(
        &self,
        edges: &[RoutesToEdge],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        upsert(
            &self.routes_to_edges,
            |edge| (edge.route_table_id.clone(), edge.destination_cidr.clone()),
            edges,
        );
        Box::pin(async { Ok(()) })
    }

    fn upsert_allows_egress_rules(
        &self,
        batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        let mut guard = self.egress_rules.lock().unwrap();
        for batch in batches {
            guard.insert(batch.security_group_id.to_string(), batch.rules.to_vec());
        }
        drop(guard);
        Box::pin(async { Ok(()) })
    }

    fn upsert_allows_ingress_rules(
        &self,
        batches: &[SgRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        let mut guard = self.ingress_rules.lock().unwrap();
        for batch in batches {
            guard.insert(batch.security_group_id.to_string(), batch.rules.to_vec());
        }
        drop(guard);
        Box::pin(async { Ok(()) })
    }

    fn upsert_has_rules(
        &self,
        batches: &[NaclRuleBatch<'_>],
    ) -> BoxFuture<'_, Result<(), GraphWriteError>> {
        if self.fail_writes {
            return Box::pin(async { Err(write_failed()) });
        }
        let mut guard = self.has_rules.lock().unwrap();
        for batch in batches {
            guard.insert(batch.network_acl_id.to_string(), batch.rules.to_vec());
        }
        drop(guard);
        Box::pin(async { Ok(()) })
    }
}
