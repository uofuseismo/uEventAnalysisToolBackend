--- Purpose: Exercises the auth schema as the read_write backend role.
---
--- Run as ueatdb_read_write_user, NOT as a superuser.  A superuser
--- bypasses every privilege check, so the negative tests -- the ones
--- asserting that even the writer cannot read a password hash -- would
--- pass against a database whose grants were completely wrong.
---
--- Expects a freshly installed database with exactly one user, an
--- activated administrator named 'root', created by a superuser:
---     SELECT auth.add_user('root', 'hash-root', TRUE);
---
--- Run with ON_ERROR_STOP=1; any failed expectation raises and the run
--- stops there.  Reaching the end means everything passed.  Leaves its
--- users and keys behind for testAuthReader.sql.
---
--- Two things shape this file:
---   * NOW() is the transaction timestamp and does not advance inside a
---     statement, so anything testing the passage of time is split
---     across separate top-level statements.  Do not merge them.
---   * Postgres reports a missing EXECUTE grant and our 'not an
---     administrator' with the same SQLSTATE (42501), so the denial
---     tests match on the message too.  Otherwise a revoked grant would
---     pass a test meant to prove the actor check works.
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

--------------------------------------------------------------------------
---                       Direct table access                           ---
--------------------------------------------------------------------------
--- The headline property: the backend that writes everything still
--- cannot read a password hash.

DO $$
BEGIN
    PERFORM password_hash FROM auth.users;
    RAISE EXCEPTION 'FAIL: writer could SELECT from auth.users';
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok: writer denied auth.users';
END $$;

DO $$
BEGIN
    PERFORM 1 FROM auth.user_keys;
    RAISE EXCEPTION 'FAIL: writer could SELECT from auth.user_keys';
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok: writer denied auth.user_keys';
END $$;

DO $$
BEGIN
    PERFORM 1 FROM auth.user_schema_permissions;
    RAISE EXCEPTION 'FAIL: writer could SELECT from auth.user_schema_permissions';
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok: writer denied auth.user_schema_permissions';
END $$;

DO $$
BEGIN
    UPDATE auth.users SET is_admin = TRUE;
    RAISE EXCEPTION 'FAIL: writer could UPDATE auth.users';
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok: writer cannot promote anyone by UPDATE';
END $$;

--------------------------------------------------------------------------
---                       Ungated functions                             ---
--------------------------------------------------------------------------
--- If any of these pass, the admin layer is decoration: the backend
--- could step straight past every actor check.

DO $$
BEGIN
    PERFORM auth.add_user('sneaky', 'hash-sneaky', TRUE);
    RAISE EXCEPTION 'FAIL: writer could call auth.add_user';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'permission denied%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: writer denied auth.add_user';
END $$;

DO $$
BEGIN
    PERFORM auth.add_provisional_user('sneaky', 'hash', INTERVAL '1 hour');
    RAISE EXCEPTION 'FAIL: writer could call auth.add_provisional_user';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'permission denied%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: writer denied auth.add_provisional_user';
END $$;

DO $$
BEGIN
    PERFORM auth.remove_user('root');
    RAISE EXCEPTION 'FAIL: writer could call auth.remove_user';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'permission denied%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: writer denied auth.remove_user';
END $$;

DO $$
BEGIN
    PERFORM auth.set_user_permission('root', 'utah', 'read_write');
    RAISE EXCEPTION 'FAIL: writer could call auth.set_user_permission';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'permission denied%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: writer denied auth.set_user_permission';
END $$;

DO $$
BEGIN
    PERFORM auth.revoke_user_permission('root', 'utah');
    RAISE EXCEPTION 'FAIL: writer could call auth.revoke_user_permission';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'permission denied%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: writer denied auth.revoke_user_permission';
END $$;

DO $$
BEGIN
    PERFORM auth.require_admin('root');
    RAISE EXCEPTION 'FAIL: writer could call auth.require_admin';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'permission denied%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: writer denied auth.require_admin';
END $$;

DO $$
BEGIN
    PERFORM auth.forbid_last_admin_removal('root');
    RAISE EXCEPTION 'FAIL: writer could call auth.forbid_last_admin_removal';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'permission denied%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: writer denied auth.forbid_last_admin_removal';
END $$;

--------------------------------------------------------------------------
---                          Creating users                             ---
--------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT auth.user_is_admin('root') OR auth.count_active_admins() <> 1 THEN
        RAISE EXCEPTION 'FAIL: expected root as the only administrator';
    END IF;
    IF NOT auth.admin_add_user('root', 'alice', 'hash-alice') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user(alice) returned FALSE';
    END IF;
    IF auth.admin_add_user('root', 'alice', 'hash-again') THEN
        RAISE EXCEPTION 'FAIL: duplicate admin_add_user(alice) returned TRUE';
    END IF;
    IF auth.admin_add_user('root', ' ALICE ', 'hash-again') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user(ALICE) created a second alice';
    END IF;
    IF auth.admin_add_user('root', '', 'hash') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user accepted an empty name';
    END IF;
    IF auth.admin_add_user('root', 'bob', '') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user accepted an empty hash';
    END IF;
    IF auth.get_password_hash('Alice') IS DISTINCT FROM 'hash-alice' THEN
        RAISE EXCEPTION 'FAIL: wrong hash for alice';
    END IF;
    --- Created directly, so already activated: nothing to change.
    IF auth.user_must_change_password('alice') THEN
        RAISE EXCEPTION 'FAIL: a directly created user must change password';
    END IF;
    --- admin_add_user never makes an administrator.
    IF auth.user_is_admin('alice') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user created an administrator';
    END IF;
    IF NOT auth.record_login('alice') THEN
        RAISE EXCEPTION 'FAIL: record_login(alice) returned FALSE';
    END IF;
    RAISE NOTICE 'ok: creating users';
END $$;

--------------------------------------------------------------------------
---                            Permissions                              ---
--------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT auth.admin_set_user_permission('root', 'alice', 'utah', 'read_only') THEN
        RAISE EXCEPTION 'FAIL: could not grant alice utah';
    END IF;
    --- Upgrading is an update, not a second row.
    IF NOT auth.admin_set_user_permission('root', 'alice', 'utah', 'read_write') THEN
        RAISE EXCEPTION 'FAIL: could not upgrade alice on utah';
    END IF;
    IF auth.get_user_permission('alice', 'utah') IS DISTINCT FROM 'read_write' THEN
        RAISE EXCEPTION 'FAIL: alice should be read_write on utah';
    END IF;
    IF NOT auth.admin_set_user_permission('root', 'alice', 'ynp', 'read_only') THEN
        RAISE EXCEPTION 'FAIL: could not grant alice ynp';
    END IF;
    IF (SELECT count(*) FROM auth.list_user_schemas('alice')) <> 2 THEN
        RAISE EXCEPTION 'FAIL: alice should list two schemas';
    END IF;
    IF NOT auth.admin_revoke_user_permission('root', 'alice', 'ynp') THEN
        RAISE EXCEPTION 'FAIL: could not revoke alice ynp';
    END IF;
    IF auth.get_user_permission('alice', 'ynp') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: alice still holds ynp';
    END IF;
    IF auth.admin_set_user_permission('root', 'alice', 'atlantis', 'read_only') THEN
        RAISE EXCEPTION 'FAIL: granted an unknown schema';
    END IF;
    IF auth.admin_set_user_permission('root', 'alice', 'utah', 'wheel') THEN
        RAISE EXCEPTION 'FAIL: granted an unknown permission';
    END IF;
    IF auth.admin_set_user_permission('root', 'nobody', 'utah', 'read_only') THEN
        RAISE EXCEPTION 'FAIL: granted a permission to nobody';
    END IF;
    --- Administrator is global and separate: it confers no data access.
    IF auth.get_user_permission('root', 'utah') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: being admin implied a schema permission';
    END IF;
    RAISE NOTICE 'ok: schema permissions';
END $$;

--------------------------------------------------------------------------
---                        Admin enforcement                            ---
--------------------------------------------------------------------------
--- alice is not an administrator.  Every admin_ call must RAISE rather
--- than return FALSE, with our message rather than a grant failure.

DO $$
BEGIN
    PERFORM auth.admin_add_user('alice', 'sneaky', 'hash-sneaky');
    RAISE EXCEPTION 'FAIL: non-admin used admin_add_user';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: non-admin denied admin_add_user';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_add_provisional_user('alice', 'sneaky', 'hash',
                                            INTERVAL '1 hour');
    RAISE EXCEPTION 'FAIL: non-admin used admin_add_provisional_user';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: non-admin denied admin_add_provisional_user';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_set_user_admin('alice', 'alice', TRUE);
    RAISE EXCEPTION 'FAIL: non-admin promoted themselves';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: non-admin cannot promote themselves';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_set_user_permission('alice', 'alice', 'ynp', 'read_write');
    RAISE EXCEPTION 'FAIL: non-admin granted themselves a schema';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: non-admin denied admin_set_user_permission';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_revoke_user_permission('alice', 'root', 'utah');
    RAISE EXCEPTION 'FAIL: non-admin revoked a permission';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: non-admin denied admin_revoke_user_permission';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_reset_user_password('alice', 'root', 'hash-x',
                                           INTERVAL '1 hour', FALSE);
    RAISE EXCEPTION 'FAIL: non-admin reset a password';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: non-admin denied admin_reset_user_password';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_remove_user('alice', 'root');
    RAISE EXCEPTION 'FAIL: non-admin removed a user';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: non-admin denied admin_remove_user';
END $$;

--- An actor who does not exist is not an administrator either, and is
--- told exactly what alice was told.
DO $$
BEGIN
    PERFORM auth.admin_add_user('nobody', 'sneaky', 'hash-sneaky');
    RAISE EXCEPTION 'FAIL: a nonexistent actor created an account';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: nonexistent actor denied';
END $$;

--------------------------------------------------------------------------
---                       Provisioning users                            ---
--------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT auth.admin_add_provisional_user('root', 'dave', 'hash-dave-issued',
                                           INTERVAL '1 hour') THEN
        RAISE EXCEPTION 'FAIL: could not provision dave';
    END IF;
    IF NOT auth.user_must_change_password('dave') THEN
        RAISE EXCEPTION 'FAIL: provisional dave need not change password';
    END IF;
    --- He can log in with the issued password -- that is how he
    --- gets to the password change.
    IF auth.get_password_hash('dave') IS DISTINCT FROM 'hash-dave-issued' THEN
        RAISE EXCEPTION 'FAIL: provisional dave cannot log in';
    END IF;
    IF auth.admin_add_provisional_user('root', 'eve', 'hash', INTERVAL '0') THEN
        RAISE EXCEPTION 'FAIL: accepted a zero interval';
    END IF;
    IF auth.admin_add_provisional_user('root', 'eve', 'hash', INTERVAL '-1 hour') THEN
        RAISE EXCEPTION 'FAIL: accepted a negative interval';
    END IF;
    IF auth.admin_add_provisional_user('root', 'eve', 'hash', NULL) THEN
        RAISE EXCEPTION 'FAIL: accepted a NULL interval';
    END IF;
    IF auth.admin_add_provisional_user('root', 'alice', 'hash', INTERVAL '1 hour') THEN
        RAISE EXCEPTION 'FAIL: provisioned over an existing user';
    END IF;
    RAISE NOTICE 'ok: provisioning';
END $$;

--- An issued password must not become a permanent key.
DO $$
BEGIN
    PERFORM auth.add_user_key('dave', 'laptop', 'pk-dave-early');
    RAISE EXCEPTION 'FAIL: provisional dave registered a key';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'password change required%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: provisional user cannot add a key';
END $$;

--- Changing the password is the activation; there is no second call.
DO $$
BEGIN
    IF NOT auth.update_user_password('dave', 'hash-dave-real') THEN
        RAISE EXCEPTION 'FAIL: dave could not set his password';
    END IF;
    IF auth.user_must_change_password('dave') THEN
        RAISE EXCEPTION 'FAIL: dave still provisional after changing password';
    END IF;
    IF NOT auth.add_user_key('dave', 'laptop', 'pk-dave-laptop') THEN
        RAISE EXCEPTION 'FAIL: activated dave could not add a key';
    END IF;
    IF auth.get_user_by_key('pk-dave-laptop') IS DISTINCT FROM 'dave' THEN
        RAISE EXCEPTION 'FAIL: dave key does not resolve';
    END IF;
    RAISE NOTICE 'ok: activation by password change';
END $$;

--------------------------------------------------------------------------
---                    Provisional expiry and sweep                     ---
--------------------------------------------------------------------------
--- Separate statements from here: NOW() is frozen per transaction.

SELECT auth.admin_add_provisional_user('root', 'frank', 'hash-frank',
                                       INTERVAL '1 second');
--- alice will forget her password (no key revocation) and miss the
--- window.  She must lose the password but keep the account.
SELECT auth.add_user_key('alice', 'laptop', 'pk-alice-laptop');
SELECT auth.admin_reset_user_password('root', 'alice', 'hash-alice-issued',
                                      INTERVAL '1 second', FALSE);
SELECT pg_sleep(1.5);

--- The deadline binds on its own, before the sweep has run.  If this
--- passes only after the sweep, the timer is the real deadline.
DO $$
BEGIN
    IF auth.get_password_hash('frank') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: expired frank can still log in';
    END IF;
    IF auth.update_user_password('frank', 'hash-frank-late') THEN
        RAISE EXCEPTION 'FAIL: expired frank activated himself';
    END IF;
    IF auth.get_password_hash('alice') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: alice expired issued password still works';
    END IF;
    RAISE NOTICE 'ok: issued passwords expire without the sweep';
END $$;

DO $$
DECLARE n INTEGER;
BEGIN
    n := auth.delete_expired_provisional_users();
    IF n <> 1 THEN
        RAISE EXCEPTION 'FAIL: sweep deleted % users, expected 1 (frank)', n;
    END IF;
    IF EXISTS (SELECT 1 FROM auth.list_users() WHERE name = 'frank') THEN
        RAISE EXCEPTION 'FAIL: frank survived the sweep';
    END IF;
    --- Forgetting a password must not cost anyone their account.
    IF NOT EXISTS (SELECT 1 FROM auth.list_users() WHERE name = 'alice') THEN
        RAISE EXCEPTION 'FAIL: the sweep deleted alice, an established user';
    END IF;
    IF auth.get_user_permission('alice', 'utah') IS DISTINCT FROM 'read_write' THEN
        RAISE EXCEPTION 'FAIL: alice lost her permissions';
    END IF;
    --- A forgot-password reset is not a compromise: her key still works.
    IF auth.get_user_by_key('pk-alice-laptop') IS DISTINCT FROM 'alice' THEN
        RAISE EXCEPTION 'FAIL: alice key stopped working';
    END IF;
    RAISE NOTICE 'ok: the sweep spares established users';
END $$;

--- Still provisional, so still no new keys, even with a working old one.
DO $$
BEGIN
    PERFORM auth.add_user_key('alice', 'desktop', 'pk-alice-desktop');
    RAISE EXCEPTION 'FAIL: reset alice registered a key';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'password change required%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: a reset user cannot add a key';
END $$;

--- The remedy for a missed window is another reset.
DO $$
BEGIN
    IF NOT auth.admin_reset_user_password('root', 'alice', 'hash-alice-issued2',
                                          INTERVAL '1 hour', FALSE) THEN
        RAISE EXCEPTION 'FAIL: could not reset alice again';
    END IF;
    IF NOT auth.update_user_password('alice', 'hash-alice-new') THEN
        RAISE EXCEPTION 'FAIL: alice could not set a new password';
    END IF;
    IF auth.get_password_hash('alice') IS DISTINCT FROM 'hash-alice-new'
       OR auth.user_must_change_password('alice') THEN
        RAISE EXCEPTION 'FAIL: alice not back to normal';
    END IF;
    RAISE NOTICE 'ok: a second reset recovers a lapsed one';
END $$;

--------------------------------------------------------------------------
---                         Compromised reset                           ---
--------------------------------------------------------------------------

SELECT auth.admin_add_user('root', 'carol', 'hash-carol');
SELECT auth.add_user_key('carol', 'old', 'pk-carol-old');
SELECT auth.revoke_user_key('carol', 'old');
SELECT auth.add_user_key('carol', 'laptop', 'pk-carol-laptop');
SELECT auth.add_user_key('carol', 'intruder', 'pk-carol-intruder');
--- Separate statement so the compromise revocation gets a later NOW()
--- than the old key's, and preserving that timestamp is checkable.
SELECT pg_sleep(0.1);

DO $$
DECLARE v_old_revoked TIMESTAMPTZ;
BEGIN
    SELECT revoked INTO v_old_revoked
      FROM auth.list_user_keys('carol') WHERE key_name = 'old';
    IF auth.admin_reset_user_password('root', 'carol', 'hash', INTERVAL '1 hour',
                                      NULL) THEN
        RAISE EXCEPTION 'FAIL: reset without saying whether it is a compromise';
    END IF;
    IF NOT auth.admin_reset_user_password('root', 'carol', 'hash-carol-issued',
                                          INTERVAL '1 hour', TRUE) THEN
        RAISE EXCEPTION 'FAIL: compromised reset of carol returned FALSE';
    END IF;
    IF auth.get_user_by_key('pk-carol-laptop') IS NOT NULL
       OR auth.get_user_by_key('pk-carol-intruder') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: a key survived a compromised reset';
    END IF;
    --- Revoked, not deleted: the rows are the audit trail.
    IF (SELECT count(*) FROM auth.list_user_keys('carol')
         WHERE revoked IS NOT NULL) <> 3 THEN
        RAISE EXCEPTION 'FAIL: expected three revoked carol keys';
    END IF;
    --- And the earlier revocation keeps its own date.
    IF (SELECT revoked FROM auth.list_user_keys('carol')
         WHERE key_name = 'old') IS DISTINCT FROM v_old_revoked THEN
        RAISE EXCEPTION 'FAIL: compromised reset rewrote an old revocation';
    END IF;
    IF NOT auth.user_must_change_password('carol') THEN
        RAISE EXCEPTION 'FAIL: carol not provisional after reset';
    END IF;
    --- Only carol's keys: dave and alice are untouched.
    IF auth.get_user_by_key('pk-dave-laptop') IS DISTINCT FROM 'dave'
       OR auth.get_user_by_key('pk-alice-laptop') IS DISTINCT FROM 'alice' THEN
        RAISE EXCEPTION 'FAIL: a compromised reset touched other users';
    END IF;
    IF auth.admin_reset_user_password('root', 'nobody', 'hash', INTERVAL '1 hour',
                                      FALSE) THEN
        RAISE EXCEPTION 'FAIL: reset a nonexistent user';
    END IF;
    RAISE NOTICE 'ok: compromised reset revokes keys';
END $$;

--------------------------------------------------------------------------
---                   Provisional administrators                        ---
--------------------------------------------------------------------------
--- A new administrator holds a password that arrived by e-mail.  That
--- is not authority, and they do not count toward the total.

DO $$
BEGIN
    IF NOT auth.admin_add_provisional_user('root', 'pending_admin',
                                           'hash-pending', INTERVAL '1 hour') THEN
        RAISE EXCEPTION 'FAIL: could not provision pending_admin';
    END IF;
    IF NOT auth.admin_set_user_admin('root', 'pending_admin', TRUE) THEN
        RAISE EXCEPTION 'FAIL: could not flag pending_admin as admin';
    END IF;
    IF auth.user_is_admin('pending_admin') THEN
        RAISE EXCEPTION 'FAIL: a provisional admin counts as an admin';
    END IF;
    IF auth.count_active_admins() <> 1 THEN
        RAISE EXCEPTION 'FAIL: a provisional admin was counted';
    END IF;
    IF auth.admin_set_user_admin('root', 'nobody', TRUE) THEN
        RAISE EXCEPTION 'FAIL: promoted a nonexistent user';
    END IF;
    IF auth.admin_set_user_admin('root', 'pending_admin', NULL) THEN
        RAISE EXCEPTION 'FAIL: accepted a NULL admin flag';
    END IF;
    RAISE NOTICE 'ok: a provisional admin is not yet an admin';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_add_user('pending_admin', 'sneaky', 'hash-sneaky');
    RAISE EXCEPTION 'FAIL: a provisional admin created an account';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: provisional admin denied until activated';
END $$;

--- Activating turns the authority on, with no separate grant step.
DO $$
BEGIN
    IF NOT auth.update_user_password('pending_admin', 'hash-pending-real') THEN
        RAISE EXCEPTION 'FAIL: pending_admin could not activate';
    END IF;
    IF NOT auth.user_is_admin('pending_admin') THEN
        RAISE EXCEPTION 'FAIL: activation did not confer admin';
    END IF;
    IF NOT auth.admin_add_user('pending_admin', 'made_by_pending', 'hash-mbp') THEN
        RAISE EXCEPTION 'FAIL: activated admin still cannot act';
    END IF;
    IF NOT auth.admin_remove_user('root', 'made_by_pending') THEN
        RAISE EXCEPTION 'FAIL: could not remove made_by_pending';
    END IF;
    RAISE NOTICE 'ok: activating a provisional admin confers authority';
END $$;

--------------------------------------------------------------------------
---                       Last-admin protection                         ---
--------------------------------------------------------------------------
--- Checked from both sides: it must NOT fire while a second admin
--- exists, and must fire once they are gone.

DO $$
BEGIN
    IF auth.count_active_admins() <> 2 THEN
        RAISE EXCEPTION 'FAIL: expected 2 active admins, found %',
                        auth.count_active_admins();
    END IF;
    IF NOT auth.admin_set_user_admin('pending_admin', 'root', FALSE) THEN
        RAISE EXCEPTION 'FAIL: could not demote an admin while another exists';
    END IF;
    IF auth.user_is_admin('root') THEN
        RAISE EXCEPTION 'FAIL: root still an admin after demotion';
    END IF;
    IF NOT auth.admin_set_user_admin('pending_admin', 'root', TRUE) THEN
        RAISE EXCEPTION 'FAIL: could not restore root';
    END IF;
    IF NOT auth.admin_remove_user('root', 'pending_admin') THEN
        RAISE EXCEPTION 'FAIL: could not remove the second admin';
    END IF;
    IF auth.count_active_admins() <> 1 THEN
        RAISE EXCEPTION 'FAIL: expected 1 active admin, found %',
                        auth.count_active_admins();
    END IF;
    RAISE NOTICE 'ok: down to a single administrator';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_set_user_admin('root', 'root', FALSE);
    RAISE EXCEPTION 'FAIL: the last admin demoted themselves';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'refusing%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: refused to demote the last admin';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_remove_user('root', 'root');
    RAISE EXCEPTION 'FAIL: the last admin deleted themselves';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'refusing%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: refused to delete the last admin';
END $$;

--- A reset makes the target provisional, and a provisional admin cannot
--- act -- the same lockout in a different hat, and the easiest to miss.
--- Both kinds of reset.
DO $$
BEGIN
    PERFORM auth.admin_reset_user_password('root', 'root', 'hash-reset',
                                           INTERVAL '1 hour', FALSE);
    RAISE EXCEPTION 'FAIL: the last admin reset themselves into a lockout';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'refusing%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: refused to reset the last admin';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_reset_user_password('root', 'root', 'hash-reset',
                                           INTERVAL '1 hour', TRUE);
    RAISE EXCEPTION 'FAIL: the last admin compromise-reset themselves';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'refusing%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: refused to compromise-reset the last admin';
END $$;

DO $$
BEGIN
    --- The last admin is otherwise unrestricted.
    IF NOT auth.admin_set_user_admin('root', 'root', TRUE) THEN
        RAISE EXCEPTION 'FAIL: last admin cannot re-assert themselves';
    END IF;
    IF auth.user_is_admin('root') IS NOT TRUE
       OR auth.get_password_hash('root') IS DISTINCT FROM 'hash-root' THEN
        RAISE EXCEPTION 'FAIL: root changed by the refused calls';
    END IF;
    --- Demoting a non-admin is not a lockout and never takes locks.
    IF NOT auth.admin_set_user_admin('root', 'alice', FALSE) THEN
        RAISE EXCEPTION 'FAIL: could not demote a non-admin';
    END IF;
    RAISE NOTICE 'ok: the last admin is otherwise unrestricted';
END $$;

--------------------------------------------------------------------------
---                           Removal                                   ---
--------------------------------------------------------------------------

SELECT auth.admin_add_user('root', 'gone', 'hash-gone');
SELECT auth.add_user_key('gone', 'laptop', 'pk-gone');
SELECT auth.admin_set_user_permission('root', 'gone', 'forge', 'read_only');

DO $$
BEGIN
    IF NOT auth.admin_remove_user('root', 'GONE') THEN
        RAISE EXCEPTION 'FAIL: could not remove gone';
    END IF;
    IF auth.get_user_by_key('pk-gone') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: a removed user key still resolves';
    END IF;
    IF auth.get_user_permission('gone', 'forge') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: a removed user kept a permission';
    END IF;
    IF auth.admin_remove_user('root', 'gone') THEN
        RAISE EXCEPTION 'FAIL: removed gone twice';
    END IF;
    RAISE NOTICE 'ok: removal cascades';
END $$;

--------------------------------------------------------------------------
---                           Listing users                             ---
--------------------------------------------------------------------------

DO $$
BEGIN
    IF (SELECT array_agg(name ORDER BY name) FROM auth.list_users())
       IS DISTINCT FROM ARRAY['alice', 'carol', 'dave', 'root'] THEN
        RAISE EXCEPTION 'FAIL: unexpected users: %',
            (SELECT array_agg(name ORDER BY name) FROM auth.list_users());
    END IF;
    IF EXISTS (SELECT 1 FROM pg_proc p
                 JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'auth' AND p.proname = 'list_users'
                  AND 'password_hash' = ANY(p.proargnames)) THEN
        RAISE EXCEPTION 'FAIL: list_users exposes password_hash';
    END IF;
    RAISE NOTICE 'ok: list_users';
END $$;

\echo 'testAuthWriter.sql: ALL PASSED'
