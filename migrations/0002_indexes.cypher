// Migration: 0002_indexes
// Purpose: indexes on fields reachability queries filter by. See
// crates/core/docs/schema.md cross-cutting notes.
//
// Statement delimiter contract: same as 0001_constraints.cypher — split on
// `;`, comments and blank lines ignored.
//
// Naming convention: `<node_type_snake_case>_<field>_idx` for node property
// indexes, `<edge_type_snake_case>_<field>_idx` for relationship property
// indexes.

// account_id — carried on every node type.
CREATE INDEX eni_account_id_idx IF NOT EXISTS
FOR (n:ENI) ON (n.account_id);

CREATE INDEX security_group_account_id_idx IF NOT EXISTS
FOR (n:SecurityGroup) ON (n.account_id);

CREATE INDEX network_acl_account_id_idx IF NOT EXISTS
FOR (n:NetworkACL) ON (n.account_id);

CREATE INDEX subnet_account_id_idx IF NOT EXISTS
FOR (n:Subnet) ON (n.account_id);

CREATE INDEX vpc_account_id_idx IF NOT EXISTS
FOR (n:VPC) ON (n.account_id);

CREATE INDEX route_table_account_id_idx IF NOT EXISTS
FOR (n:RouteTable) ON (n.account_id);

CREATE INDEX regulated_boundary_account_id_idx IF NOT EXISTS
FOR (n:RegulatedBoundary) ON (n.account_id);

// vpc_id — carried on every node type except RegulatedBoundary and VPC
// itself (VPC's own key is the vpc id).
CREATE INDEX eni_vpc_id_idx IF NOT EXISTS
FOR (n:ENI) ON (n.vpc_id);

CREATE INDEX security_group_vpc_id_idx IF NOT EXISTS
FOR (n:SecurityGroup) ON (n.vpc_id);

CREATE INDEX network_acl_vpc_id_idx IF NOT EXISTS
FOR (n:NetworkACL) ON (n.vpc_id);

CREATE INDEX subnet_vpc_id_idx IF NOT EXISTS
FOR (n:Subnet) ON (n.vpc_id);

CREATE INDEX route_table_vpc_id_idx IF NOT EXISTS
FOR (n:RouteTable) ON (n.vpc_id);

// resolved — on the evaluable-rule edges, so unresolved references can be
// listed cheaply.
CREATE INDEX allows_egress_resolved_idx IF NOT EXISTS
FOR ()-[r:ALLOWS_EGRESS]-() ON (r.resolved);

CREATE INDEX allows_ingress_resolved_idx IF NOT EXISTS
FOR ()-[r:ALLOWS_INGRESS]-() ON (r.resolved);
