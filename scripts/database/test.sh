#!/usr/bin/env bash
# Purpose: Builds a throwaway database with create.sh, runs the test
# suites against it as the backend roles, and drops it again.
#
#   ./test.sh
#   ./test.sh --keep          # leave the database up for poking at
#
# Connects as a superuser through the usual libpq environment (PGHOST,
# PGPORT, PGUSER, PGPASSWORD), exactly as create.sh does.
#
# The suites run as the backend login roles, NOT as a superuser: a
# superuser bypasses every privilege check, so the negative tests would
# pass against a database with no grants at all.  Those roles connect
# over TCP (PGHOST, or localhost), because a unix-socket connection
# usually lands on peer authentication, which maps to your OS user and
# cannot authenticate as a test role whatever password it is given.
#
# Author: Ben Baker (University of Utah)
# License: MIT NO AI license
set -euo pipefail

###########################################################################
###                          CONFIGURATION                              ###
###########################################################################

# Deliberately not ueatdb.  This script drops whatever it is pointed at.
TEST_DB="${TEST_DB:-ueatdb_selftest}"

# Names this script refuses to touch no matter what.  Add every real
# deployment here; the cost of a wrong answer is the whole database.
PROTECTED_DBS=("ueatdb" "postgres" "template0" "template1")

ADMIN_DB="${ADMIN_DB:-postgres}"

# Roles are cluster-wide, so the test uses its own rather than rotating
# the passwords on the roles a running backend authenticates with.
TEST_RW_ROLE="ueatdb_selftest_read_write"
TEST_RO_ROLE="ueatdb_selftest_read_only"
TEST_RW_USER="ueatdb_selftest_read_write_user"
TEST_RO_USER="ueatdb_selftest_read_only_user"

TEST_HOST="${PGHOST:-localhost}"
if [[ ${TEST_HOST} == /* ]]; then
  echo "NOTE: PGHOST is a socket directory; test roles will use localhost." >&2
  TEST_HOST=localhost
fi

###########################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEEP=0
[[ ${1:-} == "--keep" ]] && KEEP=1

for protected in "${PROTECTED_DBS[@]}"; do
  if [[ ${TEST_DB} == "${protected}" ]]; then
    echo "ABORTING: refusing to run tests against '${TEST_DB}'." >&2
    echo "          This script drops the database it is given." >&2
    exit 1
  fi
done

# Throwaway passwords, regenerated per run and never written down.
TEST_RW_PASSWORD="selftest_rw_$RANDOM$RANDOM$RANDOM"
TEST_RO_PASSWORD="selftest_ro_$RANDOM$RANDOM$RANDOM"

as_superuser() {
  psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 "$@"
}

cleanup() {
  local rc=$?
  if [[ ${KEEP} -eq 1 ]]; then
    echo
    echo "Left ${TEST_DB} in place (--keep)."
    echo "  psql --host=${TEST_HOST} --dbname=${TEST_DB} --username=${TEST_RW_USER}"
    echo "  password: ${TEST_RW_PASSWORD}"
    return $rc
  fi
  echo
  echo "==> dropping ${TEST_DB}"
  as_superuser --dbname="${ADMIN_DB}" \
       -c "DROP DATABASE IF EXISTS \"${TEST_DB}\" WITH (FORCE);" >/dev/null 2>&1 || true
  # Roles are cluster-wide, so a leftover set would collide with the
  # next run.  They own nothing once the database is gone.
  for r in "${TEST_RW_USER}" "${TEST_RO_USER}" "${TEST_RW_ROLE}" "${TEST_RO_ROLE}"; do
    as_superuser --dbname="${ADMIN_DB}" \
         -c "DROP ROLE IF EXISTS \"${r}\";" >/dev/null 2>&1 || true
  done
  return $rc
}
trap cleanup EXIT

###########################################################################
###                             BUILD                                   ###
###########################################################################

echo "==> building ${TEST_DB}"
DROP_EXISTING=1 \
DROP_ROLES=1 \
ADMIN_DB="${ADMIN_DB}" \
RW_ROLE="${TEST_RW_ROLE}" \
RO_ROLE="${TEST_RO_ROLE}" \
UEATDB_RW_USER="${TEST_RW_USER}" \
UEATDB_RO_USER="${TEST_RO_USER}" \
RW_PASSWORD_ENV=TEST_RW_PASSWORD \
RO_PASSWORD_ENV=TEST_RO_PASSWORD \
TEST_RW_PASSWORD="${TEST_RW_PASSWORD}" \
TEST_RO_PASSWORD="${TEST_RO_PASSWORD}" \
  "${SCRIPT_DIR}/create.sh" "${TEST_DB}" >/dev/null

###########################################################################
###                           BOOTSTRAP                                 ###
###########################################################################

# The first administrator cannot be created through the admin functions,
# because every one of them demands an existing administrator.  add_user
# is granted to no role precisely so that this is a superuser step --
# which is also how a real deployment breaks the same cycle.
echo "==> bootstrapping the first administrator"
as_superuser --dbname="${TEST_DB}" \
     -c "SELECT auth.add_user('root', 'hash-root', TRUE);" >/dev/null

###########################################################################
###                              RUN                                    ###
###########################################################################

# as_role <rw|ro> [psql args...]
as_role() {
  local which=$1; shift
  local user=${TEST_RW_USER} password=${TEST_RW_PASSWORD}
  if [[ ${which} == ro ]]; then
    user=${TEST_RO_USER}; password=${TEST_RO_PASSWORD}
  fi
  PGPASSWORD="${password}" psql --no-psqlrc --quiet \
       --set=ON_ERROR_STOP=1 \
       --host="${TEST_HOST}" \
       --dbname="${TEST_DB}" \
       --username="${user}" \
       "$@"
}

# run_suite <rw|ro> <file>
#
# ON_ERROR_STOP turns the first failed expectation into a non-zero exit,
# so a suite that prints 'ALL PASSED' really did reach the end.  Query
# output is discarded; the NOTICEs on stderr are the running commentary.
run_suite() {
  echo
  echo "==> $2 as $1"
  as_role "$1" --output=/dev/null --file="${SCRIPT_DIR}/tests/$2"
}

# The writer suite runs first and leaves users and keys behind; the
# reader suite reads that state rather than building its own.  They are
# not independent and the order is not arbitrary.
run_suite rw testAuthWriter.sql
run_suite ro testAuthReader.sql

###########################################################################
###                    Concurrent last-admin removal                    ###
###########################################################################
# Two administrators each remove the other at the same moment.  Without
# the FOR UPDATE in auth.forbid_last_admin_removal both would count two,
# both would succeed, and nobody would be left -- write skew, which no
# single-session test can show.  Needs two connections, so it lives here
# rather than in a .sql suite.

echo
echo "==> concurrent removal of the last two administrators"
as_role rw --output=/dev/null <<'SQL'
SELECT auth.admin_add_user('root', 'admin_one', 'hash-one');
SELECT auth.admin_add_user('root', 'admin_two', 'hash-two');
SELECT auth.admin_set_user_admin('root', 'admin_one', TRUE);
SELECT auth.admin_set_user_admin('root', 'admin_two', TRUE);
SELECT auth.admin_set_user_admin('admin_one', 'root', FALSE);
SQL

n_admins=$(as_role rw --tuples-only --no-align -c "SELECT auth.count_active_admins();")
if [[ ${n_admins} -ne 2 ]]; then
  echo "FAIL: race setup expected 2 administrators, found ${n_admins}" >&2
  exit 1
fi

# The first session removes admin_two and holds its transaction open;
# the second tries to remove admin_one while that lock is held.
first_log=$(mktemp)
second_log=$(mktemp)
as_role rw --tuples-only --no-align >"${first_log}" 2>&1 <<'SQL' &
BEGIN;
SELECT auth.admin_remove_user('admin_one', 'admin_two');
SELECT pg_sleep(2);
COMMIT;
SQL
first_pid=$!
sleep 0.5
second_rc=0
as_role rw --tuples-only --no-align >"${second_log}" 2>&1 <<'SQL' || second_rc=$?
BEGIN;
SELECT auth.admin_remove_user('admin_two', 'admin_one');
COMMIT;
SQL
first_rc=0
wait "${first_pid}" || first_rc=$?

admins=$(as_role rw --tuples-only --no-align \
           -c "SELECT string_agg(name, ',' ORDER BY name) FROM auth.list_users() WHERE auth.user_is_admin(name);")
if [[ ${first_rc} -ne 0 ]] || ! grep -q '^t$' "${first_log}"; then
  echo "FAIL: the first removal should have succeeded:" >&2
  cat "${first_log}" >&2
  exit 1
fi
if [[ ${second_rc} -eq 0 ]] \
   || ! grep -q 'refusing to leave the database with no administrator' "${second_log}"; then
  echo "FAIL: the second removal should have been refused:" >&2
  cat "${second_log}" >&2
  exit 1
fi
if [[ ${admins} != "admin_one" ]]; then
  echo "FAIL: expected admin_one as the only administrator, found '${admins}'" >&2
  exit 1
fi
rm -f "${first_log}" "${second_log}"
echo "ok: the second administrator waited, re-counted, and was refused"

echo
echo "ALL DATABASE TESTS PASSED"
