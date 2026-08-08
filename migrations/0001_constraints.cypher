// Migration: 0001_constraints
// Purpose: uniqueness constraints on the AWS ID (or operator-assigned key,
// for RegulatedBoundary) of every node type documented in
// crates/core/docs/schema.md.
//
// Statement delimiter contract (relied on by the M0-T4 runner): each
// statement is terminated by a semicolon `;`. Blank lines and comment lines
// (`//`) are not delimiters and may appear freely between or inside
// statements. The runner splits this file on `;` and executes each
// resulting non-empty, non-comment-only chunk as one statement.
//
// Naming convention: `<node_type_snake_case>_id_unique`.

CREATE CONSTRAINT eni_id_unique IF NOT EXISTS
FOR (n:ENI) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT security_group_id_unique IF NOT EXISTS
FOR (n:SecurityGroup) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT network_acl_id_unique IF NOT EXISTS
FOR (n:NetworkACL) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT subnet_id_unique IF NOT EXISTS
FOR (n:Subnet) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT vpc_id_unique IF NOT EXISTS
FOR (n:VPC) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT route_table_id_unique IF NOT EXISTS
FOR (n:RouteTable) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT regulated_boundary_id_unique IF NOT EXISTS
FOR (n:RegulatedBoundary) REQUIRE n.id IS UNIQUE;
