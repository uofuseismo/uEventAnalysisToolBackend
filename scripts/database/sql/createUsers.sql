--- Purpose: Creates the backend roles (the postgres-level identities the
--- backend connects as).  Privileges are granted later, once the
--- objects they name exist.  Runs against the maintenance database as a
--- superuser.
---
--- Expects these psql variables (set by create.sh):
---   drop_roles, rw_role, ro_role, rw_user, ro_user,
---   rw_password, ro_password
---
--- Variables are never referenced inside dollar-quoted blocks -- psql
--- does not expand them there -- so idempotent DDL is done with \gexec.
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

--- Roles are cluster-wide, so dropping them is opt-in and separate from
--- dropping the database: another database on this server (a test
--- system, say) may still be using them.  PostgreSQL refuses the drop
--- if anything still depends on the role, which is the behaviour you
--- want.
\if :drop_roles
DROP ROLE IF EXISTS :"rw_user";
DROP ROLE IF EXISTS :"ro_user";
DROP ROLE IF EXISTS :"rw_role";
DROP ROLE IF EXISTS :"ro_role";
\endif

--- Two group roles carry the privileges; two login roles are members of
--- them.  Grants go to the groups, so a second writer login is one
--- GRANT rather than a re-run of the grant files.
SELECT format('CREATE ROLE %I NOLOGIN', :'rw_role')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'rw_role')
\gexec

SELECT format('CREATE ROLE %I NOLOGIN', :'ro_role')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'ro_role')
\gexec

SELECT format('CREATE ROLE %I LOGIN', :'rw_user')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'rw_user')
\gexec

SELECT format('CREATE ROLE %I LOGIN', :'ro_user')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'ro_user')
\gexec

--- Set the passwords unconditionally, so re-running the installer with a
--- new password rotates it.  %L quotes the literal; the value arrived on
--- stdin rather than argv, so it was never visible in ps.
SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L', :'rw_user', :'rw_password')
\gexec

SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L', :'ro_user', :'ro_password')
\gexec

SELECT format('GRANT %I TO %I', :'rw_role', :'rw_user')
\gexec

SELECT format('GRANT %I TO %I', :'ro_role', :'ro_user')
\gexec
