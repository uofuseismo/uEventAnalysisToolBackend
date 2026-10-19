--- Purpose: Creates the database, the auth schema, and the external
--- schema.  Region schemas (and their sandboxes) are created by
--- createRegionCore.sql, driven by create.sh.  Runs against the
--- maintenance database (e.g., postgres) as a superuser.
---
--- Expects these psql variables (set by create.sh):
---   db_name, drop_existing
---
--- Names are interpolated as :"name" (a quoted identifier) rather than
--- :name, so an awkward deployment name cannot silently fold or break.
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

--- Guard so a stray run in production cannot nuke the database.  With
--- the guard off, CREATE DATABASE below fails on an existing database,
--- which is the behaviour you want.
\if :drop_existing
DROP DATABASE IF EXISTS :"db_name";
\endif

CREATE DATABASE :"db_name";
\connect :"db_name"

--- By default every role in the cluster can connect to (and create
--- temporary tables in) every database.  Revoke that; createGrants.sql
--- hands CONNECT back to the two backend roles only.
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;

--- PUBLIC can create objects in 'public' on PostgreSQL 14 and older.
--- Harmless to repeat on 15+, where it is already the default.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

--- Application-level auth lives here (frontend users, permissions).
CREATE SCHEMA auth;
--- Data from external agencies/networks.
CREATE SCHEMA external;
