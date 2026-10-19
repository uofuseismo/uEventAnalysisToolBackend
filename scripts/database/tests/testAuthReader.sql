--- Purpose: Exercises the auth schema as the read_only backend role.
---
--- Almost every test here is a negative one.  The writer suite proves
--- the functions work; this one proves the reader cannot reach the ones
--- it should not, which is the half that fails silently -- a missing
--- REVOKE breaks nothing, it just quietly grants everyone EXECUTE.
---
--- Run as ueatdb_read_only_user, AFTER testAuthWriter.sql: it reads the
--- users and keys that suite leaves behind.  Run with ON_ERROR_STOP=1.
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

--------------------------------------------------------------------------
---                       Direct table access                           ---
--------------------------------------------------------------------------

DO $$
BEGIN
    PERFORM password_hash FROM auth.users;
    RAISE EXCEPTION 'FAIL: reader could SELECT from auth.users';
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok: reader denied auth.users';
END $$;

DO $$
BEGIN
    PERFORM 1 FROM auth.user_keys;
    RAISE EXCEPTION 'FAIL: reader could SELECT from auth.user_keys';
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok: reader denied auth.user_keys';
END $$;

--------------------------------------------------------------------------
---                     Functions the reader may call                   ---
--------------------------------------------------------------------------
--- Verifying a login is a read, so the reader gets the hash to check
--- against.  Recording that it happened is a write, and is denied below.

DO $$
BEGIN
    IF auth.get_password_hash('alice') IS DISTINCT FROM 'hash-alice-new' THEN
        RAISE EXCEPTION 'FAIL: reader could not fetch alice hash';
    END IF;
    IF auth.get_user_by_key('pk-dave-laptop') IS DISTINCT FROM 'dave' THEN
        RAISE EXCEPTION 'FAIL: reader could not resolve a key';
    END IF;
    IF auth.get_user_permission('alice', 'utah') IS DISTINCT FROM 'read_write' THEN
        RAISE EXCEPTION 'FAIL: reader could not read a permission';
    END IF;
    IF NOT auth.user_must_change_password('carol') THEN
        RAISE EXCEPTION 'FAIL: reader could not see carol is provisional';
    END IF;
    IF NOT auth.user_is_admin('root') OR auth.count_active_admins() <> 1 THEN
        RAISE EXCEPTION 'FAIL: reader could not read admin state';
    END IF;
    PERFORM * FROM auth.list_user_schemas('alice');
    PERFORM * FROM auth.list_user_keys('alice');
    PERFORM * FROM auth.list_users();
    RAISE NOTICE 'ok: reader can verify and look up';
END $$;

--------------------------------------------------------------------------
---                   Functions the reader may NOT call                 ---
--------------------------------------------------------------------------
--- Each is checked for a GRANT failure specifically.  The admin_ ones
--- would also fail the actor check if 'alice' were the actor, so 'root'
--- is used: only a missing grant can stop these.

--- Inline rather than a temporary table: the reader holds no TEMP
--- privilege on the database, and that is how it should stay.
DO $$
DECLARE r RECORD;
        n INTEGER := 0;
BEGIN
    FOR r IN SELECT call FROM (VALUES
    ($q$SELECT auth.add_user('sneaky', 'hash', TRUE)$q$),
    ($q$SELECT auth.add_provisional_user('sneaky', 'hash', INTERVAL '1 hour')$q$),
    ($q$SELECT auth.remove_user('alice')$q$),
    ($q$SELECT auth.set_user_permission('alice', 'ynp', 'read_write')$q$),
    ($q$SELECT auth.revoke_user_permission('alice', 'utah')$q$),
    ($q$SELECT auth.require_admin('root')$q$),
    ($q$SELECT auth.forbid_last_admin_removal('root')$q$),
    ($q$SELECT auth.admin_add_user('root', 'sneaky', 'hash')$q$),
    ($q$SELECT auth.admin_add_provisional_user('root', 'sneaky', 'hash', INTERVAL '1 hour')$q$),
    ($q$SELECT auth.admin_set_user_admin('root', 'alice', TRUE)$q$),
    ($q$SELECT auth.admin_set_user_permission('root', 'alice', 'ynp', 'read_write')$q$),
    ($q$SELECT auth.admin_revoke_user_permission('root', 'alice', 'utah')$q$),
    ($q$SELECT auth.admin_reset_user_password('root', 'alice', 'hash', INTERVAL '1 hour', TRUE)$q$),
    ($q$SELECT auth.admin_remove_user('root', 'alice')$q$),
    ($q$SELECT auth.update_user_password('alice', 'hash')$q$),
    ($q$SELECT auth.record_login('alice')$q$),
    ($q$SELECT auth.add_user_key('alice', 'sneaky', 'pk-sneaky')$q$),
    ($q$SELECT auth.revoke_user_key('alice', 'laptop')$q$),
    ($q$SELECT auth.record_key_use('pk-alice-laptop')$q$),
    --- The sweep deletes rows.  A reader holding it could empty the
    --- pending-user list.
    ($q$SELECT auth.delete_expired_provisional_users()$q$)
    ) AS forbidden(call) LOOP
        n := n + 1;
        BEGIN
            EXECUTE r.call;
            RAISE EXCEPTION 'FAIL: reader ran %', r.call;
        EXCEPTION WHEN insufficient_privilege THEN
            IF SQLERRM NOT LIKE 'permission denied%' THEN
                RAISE EXCEPTION 'FAIL: % refused for the wrong reason: %',
                                r.call, SQLERRM;
            END IF;
        END;
    END LOOP;
    RAISE NOTICE 'ok: reader denied % mutating functions', n;
END $$;

\echo 'testAuthReader.sql: ALL PASSED'
