--- Purpose: Grants privileges for the database and the auth schema.
--- Run after all objects exist; expects the psql variables db_name,
--- rw_role, and ro_role (set by create.sh).  Region-schema grants are in
--- grantRegionPrivileges.sql, driven per-schema by create.sh.
---
--- Philosophy:
---   * The auth tables are reachable ONLY through the auth functions.
---     Backend roles get EXECUTE, never direct table access, so even
---     the read_write backend cannot SELECT password hashes.
---   * Functions therefore become SECURITY DEFINER (they run with the
---     owner's privileges, not the caller's), with search_path pinned,
---     which is the standard hardening for definer functions.
---   * Postgres grants EXECUTE on new functions to PUBLIC by default.
---     We revoke everything wholesale, then re-grant deliberately.
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

--- Let the backend roles in the front door.
GRANT CONNECT ON DATABASE :"db_name" TO :"rw_role", :"ro_role";

--------------------------------------------------------------------------
---                            auth schema                              ---
--------------------------------------------------------------------------
--- USAGE lets a role reference objects in the schema (needed to call
--- the functions); it does not by itself allow reading any table.
GRANT USAGE ON SCHEMA auth TO :"rw_role", :"ro_role";

--- Deliberately NO table grants in auth: no SELECT, nothing.

--- Kill the EXECUTE-to-PUBLIC default on everything in auth.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA auth FROM PUBLIC;

--- Flip the auth functions to SECURITY DEFINER so they can touch the
--- auth tables on behalf of callers who cannot.  Pin search_path
--- (belt: every reference in the bodies is schema-qualified anyway).
DO $$
DECLARE f RECORD;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure AS sig
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'auth'
    LOOP
        EXECUTE format(
            'ALTER FUNCTION %s SECURITY DEFINER SET search_path = auth, pg_temp',
            f.sig);
    END LOOP;
END;
$$;

--- User administration: read_write backend only.  Every one of these
--- also takes the acting user and refuses one who is not an activated
--- administrator, so holding the grant is necessary, not sufficient.
GRANT EXECUTE ON FUNCTION
    auth.admin_add_user(TEXT, TEXT, TEXT),
    auth.admin_add_provisional_user(TEXT, TEXT, TEXT, INTERVAL),
    auth.admin_set_user_admin(TEXT, TEXT, BOOLEAN),
    auth.admin_set_user_permission(TEXT, TEXT, TEXT, TEXT),
    auth.admin_revoke_user_permission(TEXT, TEXT, TEXT),
    auth.admin_reset_user_password(TEXT, TEXT, TEXT, INTERVAL, BOOLEAN),
    auth.admin_remove_user(TEXT, TEXT)
    TO :"rw_role";

--- Self-service mutations: read_write backend only.  These act on the
--- caller's own account, so they take no actor; the backend must take
--- the name from the authenticated session, never from the request.
GRANT EXECUTE ON FUNCTION
    auth.update_user_password(TEXT, TEXT),
    auth.record_login(TEXT),
    auth.add_user_key(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ),
    auth.revoke_user_key(TEXT, TEXT),
    auth.record_key_use(TEXT),
    auth.delete_expired_provisional_users()
    TO :"rw_role";

--- NOT granted to either backend, deliberately: add_user,
--- add_provisional_user, remove_user, set_user_permission,
--- revoke_user_permission, require_admin, forbid_last_admin_removal.
--- The first five are the ungated versions the admin_ functions wrap --
--- reachable only by a superuser, which is how the first administrator
--- gets created:
---
---     psql -d ueatdb -c "SELECT auth.add_user('jsmith', '\$argon2id\$...', TRUE);"
---
--- The last two are internal; they run as the owner from inside the
--- definer functions and need no EXECUTE of their own.

--- Read/verify functions: both backends.  Note get_password_hash is
--- here because verifying a login IS a read; recording it is not.
GRANT EXECUTE ON FUNCTION
    auth.get_password_hash(TEXT),
    auth.user_must_change_password(TEXT),
    auth.get_user_by_key(TEXT),
    auth.get_user_permission(TEXT, TEXT),
    auth.list_user_schemas(TEXT),
    auth.list_user_keys(TEXT),
    auth.user_is_admin(TEXT),
    auth.count_active_admins(),
    auth.list_users()
    TO :"rw_role", :"ro_role";
