#!/usr/bin/env bash
# Purpose: Creates the database from scratch.
#
#   UEATDB_RW_PASSWORD=... UEATDB_RO_PASSWORD=... ./create.sh ueatdb
#
# Connects as a superuser through the usual libpq environment (PGHOST,
# PGPORT, PGUSER, PGPASSWORD); with none set, that is the local socket
# as your OS user.  Everything site-specific is in the CONFIGURATION
# block below; the .sql files take psql variables and contain no names,
# passwords, or intervals.
#
# The first administrator is created afterwards, by a superuser, because
# every admin_ function demands an existing administrator:
#
#   psql -d ueatdb -c "SELECT auth.add_user('jsmith', '\$argon2id\$...', TRUE);"
#
# Author: Ben Baker (University of Utah)
# License: MIT NO AI license
set -euo pipefail

###########################################################################
###                          CONFIGURATION                              ###
###########################################################################

# The database name is an argument rather than an edit, so a test
# database is not one typo away from the real one.  DB_NAME in the
# environment works too; the argument wins.
DB_NAME="${1:-${DB_NAME:-}}"

# Maintenance database to connect to before ours exists.
ADMIN_DB="${ADMIN_DB:-postgres}"

# Monitoring regions.  Each region gets a production schema (e.g., ynp)
# and a structurally identical sandbox schema (e.g., sandbox_ynp).
REGIONS="${REGIONS:-utah ynp forge}"

# Drop an existing database of this name first.  Off by default: with
# it off, an existing database makes the install fail rather than
# disappear.  Turn it on deliberately, for a rebuild you mean.
DROP_EXISTING="${DROP_EXISTING:-0}"

# Roles are cluster-wide and are NOT dropped by default, because another
# database on this server may share them.  PostgreSQL refuses the drop
# if anything still holds grants, which is the behaviour you want.
DROP_ROLES="${DROP_ROLES:-0}"

RW_ROLE="${RW_ROLE:-ueatdb_read_write}"
RO_ROLE="${RO_ROLE:-ueatdb_read_only}"

# The login roles the backend connects as, set alongside their passwords:
#
#     UEATDB_RW_USER=... UEATDB_RW_PASSWORD=... \
#     UEATDB_RO_USER=... UEATDB_RO_PASSWORD=... ./create.sh ueatdb
RW_USER="${UEATDB_RW_USER:-ueatdb_read_write_user}"
RO_USER="${UEATDB_RO_USER:-ueatdb_read_only_user}"

# Passwords for the two login roles come from the environment variables
# NAMED here.  They must be EXPORTED into this script's environment; a
# variable merely assigned in your shell is not, and the script says so
# and stops.  These work:
#
#     UEATDB_RW_PASSWORD=... UEATDB_RO_PASSWORD=... ./create.sh ueatdb
#     export UEATDB_RW_PASSWORD=...; ...; ./create.sh ueatdb
#
# Under sudo, put the assignments AFTER sudo: it scrubs the environment.
RW_PASSWORD_ENV="${RW_PASSWORD_ENV:-UEATDB_RW_PASSWORD}"
RO_PASSWORD_ENV="${RO_PASSWORD_ENV:-UEATDB_RO_PASSWORD}"

# A missing password aborts the install.  Set to 1 for a throwaway
# sandbox where you genuinely do not care; the roles then get a
# placeholder password.
ALLOW_PLACEHOLDER_PASSWORDS="${ALLOW_PLACEHOLDER_PASSWORDS:-0}"

###########################################################################
###                    END CONFIGURATION                                ###
###########################################################################

SQL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sql"

if [[ -z ${DB_NAME} ]]; then
  echo "usage: $0 <db_name>        # e.g. $0 ueatdb" >&2
  exit 1
fi

# Escape a value for psql's \set '...' string syntax.
psql_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\'/\\\'}
  printf '%s' "$s"
}

# resolve_password <label> <env var name> <user>
#
# Prints the password, or CHANGE plus a diagnosis on stderr.  ${!name+x}
# is what separates 'not exported' from 'exported but empty'.
resolve_password() {
  local label=$1 env_name=$2 user=$3
  if [[ -z ${!env_name+x} ]]; then
    echo "WARNING: \$${env_name} is not set in this script's environment." >&2
    echo "         If you assigned it in your shell, it needs exporting." >&2
    echo "         ${user} (${label}) would get a placeholder password." >&2
    printf 'CHANGE'
    return
  fi
  if [[ -z ${!env_name} ]]; then
    echo "WARNING: \$${env_name} is exported but empty." >&2
    echo "         ${user} (${label}) would get a placeholder password." >&2
    printf 'CHANGE'
    return
  fi
  printf '%s' "${!env_name}"
}

SECRET_RW_PASSWORD=$(resolve_password RW "${RW_PASSWORD_ENV}" "${RW_USER}")
SECRET_RO_PASSWORD=$(resolve_password RO "${RO_PASSWORD_ENV}" "${RO_USER}")

if [[ ${SECRET_RW_PASSWORD} == "CHANGE" || ${SECRET_RO_PASSWORD} == "CHANGE" ]]; then
  if [[ ${ALLOW_PLACEHOLDER_PASSWORDS} -ne 1 ]]; then
    echo >&2
    echo "ABORTING: at least one role would get a placeholder password." >&2
    echo "          Fix the warnings above, or set" >&2
    echo "          ALLOW_PLACEHOLDER_PASSWORDS=1 for a throwaway sandbox." >&2
    exit 1
  fi
  echo "WARNING: continuing with placeholder passwords." >&2
fi

# run_sql <file> <dbname> [extra --set args...]
#
# Secrets go in via \set on stdin; argv is world-visible in ps, stdin is
# not.  Everything else goes through --set, which keeps it readable.
run_sql() {
  local file="$1"; shift
  local dbname="$1"; shift
  echo "==> ${file}  (db=${dbname})${*:+  $*}"
  # Silences the 'does not exist, skipping' NOTICE from every DROP IF
  # EXISTS on a fresh install; warnings and errors still come through.
  PGOPTIONS="${PGOPTIONS:-} -c client_min_messages=warning" \
  psql --no-psqlrc --quiet \
       --set=ON_ERROR_STOP=1 \
       --dbname="${dbname}" \
       --set=db_name="${DB_NAME}" \
       --set=drop_existing="${DROP_EXISTING}" \
       --set=drop_roles="${DROP_ROLES}" \
       --set=rw_role="${RW_ROLE}" \
       --set=ro_role="${RO_ROLE}" \
       --set=rw_user="${RW_USER}" \
       --set=ro_user="${RO_USER}" \
       "$@" <<EOF
\set rw_password '$(psql_escape "${SECRET_RW_PASSWORD}")'
\set ro_password '$(psql_escape "${SECRET_RO_PASSWORD}")'
\i ${SQL_DIR}/${file}
EOF
}

###########################################################################
###                            INSTALL                                  ###
###########################################################################

# 1) Database itself, plus the auth and external schemas.  CREATE
#    DATABASE cannot run inside a transaction, so this is its own call.
run_sql createDatabase.sql "${ADMIN_DB}"

# 2) Backend roles (postgres-level identities the backend connects as).
run_sql createUsers.sql "${ADMIN_DB}"

# 3) Application-level auth: frontend users table + login functions.
run_sql createUsersTable.sql "${DB_NAME}"

# 4) Application-level authorization: schemas/permissions lookup tables
#    and the user -> (schema, permission) mapping.
run_sql createPermissionsTables.sql "${DB_NAME}"

# 4b) User administration: admin_ wrappers over (3) and (4), with the
#     actor check and last-administrator protection.
run_sql createAdministration.sql "${DB_NAME}"

# 5) Region schemas: shared core tables plus region-specific extensions,
#    then a structurally identical sandbox for each region.
#    createRegionCore.sql is responsible for DROP/CREATE of the schema
#    named in :target_schema.
for region in ${REGIONS}; do
  for schema in "${region}" "sandbox_${region}"; do
    run_sql createRegionCore.sql "${DB_NAME}" --set=target_schema="${schema}"
    run_sql "regions/${region}.sql" "${DB_NAME}" --set=target_schema="${schema}"
    run_sql grantRegionPrivileges.sql "${DB_NAME}" --set=target_schema="${schema}"
  done
done

# 6) Global grants: database CONNECT and the auth schema doorway.
#    Runs last so every object it references exists.
run_sql createGrants.sql "${DB_NAME}"

echo
echo "Installed ${DB_NAME}"
echo "  writer=${RW_USER} (\$${RW_PASSWORD_ENV})  reader=${RO_USER} (\$${RO_PASSWORD_ENV})"
