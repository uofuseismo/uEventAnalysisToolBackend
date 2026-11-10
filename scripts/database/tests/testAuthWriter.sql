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
---   * auth.user_keys accepts only real-shaped ed25519 keys, so a test
---     key is encode(sha256('pk-<label>'), 'base64'): 32 bytes, padded
---     base64, and the same every time it is written.
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
    PERFORM 1 FROM auth.consumed_assertions;
    RAISE EXCEPTION 'FAIL: writer could SELECT from auth.consumed_assertions';
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'ok: writer denied auth.consumed_assertions';
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
    --- Names are [a-z0-9._@-]{1,64} after trimming and lower-casing.
    --- A bad name is FALSE like any other bad input, not an error.
    IF auth.admin_add_user('root', 'b o b', 'hash') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user accepted a name with a space';
    END IF;
    IF auth.admin_add_user('root', 'bob;drop', 'hash') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user accepted a name with a semicolon';
    END IF;
    IF auth.admin_add_provisional_user('root', 'bøb', 'hash',
                                       INTERVAL '1 hour') THEN
        RAISE EXCEPTION 'FAIL: admin_add_provisional_user accepted a non-ASCII name';
    END IF;
    IF auth.admin_add_user('root', repeat('a', 65), 'hash') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user accepted a 65-character name';
    END IF;
    IF auth.admin_add_provisional_user('root', repeat('a', 65), 'hash',
                                       INTERVAL '1 hour') THEN
        RAISE EXCEPTION 'FAIL: admin_add_provisional_user accepted a 65-character name';
    END IF;
    IF NOT auth.admin_add_user('root', repeat('a', 64), 'hash') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user refused a 64-character name';
    END IF;
    IF NOT auth.admin_add_user('root', ' Sam-I.Am_2@Example.org ', 'hash') THEN
        RAISE EXCEPTION 'FAIL: admin_add_user refused an email-style name';
    END IF;
    IF auth.get_user_name('sam-i.am_2@example.org') IS NULL THEN
        RAISE EXCEPTION 'FAIL: email-style name not stored canonically';
    END IF;
    IF NOT auth.admin_remove_user('root', repeat('a', 64))
       OR NOT auth.admin_remove_user('root', 'sam-i.am_2@example.org') THEN
        RAISE EXCEPTION 'FAIL: could not remove the name-pattern users';
    END IF;
    IF auth.get_password_hash('Alice') IS DISTINCT FROM 'hash-alice' THEN
        RAISE EXCEPTION 'FAIL: wrong hash for alice';
    END IF;
    --- Any spelling the lookups accept gives back the stored one.
    IF auth.get_user_name(' ALICE ') IS DISTINCT FROM 'alice' THEN
        RAISE EXCEPTION 'FAIL: get_user_name did not canonicalize ALICE';
    END IF;
    IF auth.get_user_name('nobody') IS NOT NULL OR
       auth.get_user_name('') IS NOT NULL OR
       auth.get_user_name(NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: get_user_name named a user who does not exist';
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
    IF auth.admin_set_user_permission('root', 'nobody', 'utah', 'read_only') THEN
        RAISE EXCEPTION 'FAIL: granted a permission to nobody';
    END IF;
    --- Nothing to revoke is FALSE, for a real user or a missing one.
    IF auth.admin_revoke_user_permission('root', 'alice', 'ynp') THEN
        RAISE EXCEPTION 'FAIL: revoked a grant alice does not hold';
    END IF;
    IF auth.admin_revoke_user_permission('root', 'nobody', 'utah') THEN
        RAISE EXCEPTION 'FAIL: revoked a grant from nobody';
    END IF;
    --- Administrator is global and separate: it confers no data access.
    IF auth.get_user_permission('root', 'utah') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: being admin implied a schema permission';
    END IF;
    RAISE NOTICE 'ok: schema permissions';
END $$;

--- An unknown schema or permission RAISEs, each with its own SQLSTATE,
--- so the backend can tell them from each other and from no such user.
--- Checked before the user, so a bad schema is reported even for nobody.
DO $$
BEGIN
    PERFORM auth.admin_set_user_permission('root', 'alice', 'atlantis', 'read_only');
    RAISE EXCEPTION 'FAIL: granted an unknown schema';
EXCEPTION WHEN invalid_parameter_value THEN
    IF SQLERRM NOT LIKE 'unknown schema%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: refused an unknown schema';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_set_user_permission('root', 'nobody', 'atlantis', 'read_only');
    RAISE EXCEPTION 'FAIL: granted nobody an unknown schema';
EXCEPTION WHEN invalid_parameter_value THEN
    IF SQLERRM NOT LIKE 'unknown schema%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: unknown schema reported before unknown user';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_set_user_permission('root', 'alice', 'utah', 'wheel');
    RAISE EXCEPTION 'FAIL: granted an unknown permission';
EXCEPTION WHEN undefined_object THEN
    IF SQLERRM NOT LIKE 'unknown permission%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: refused an unknown permission';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_revoke_user_permission('root', 'alice', 'atlantis');
    RAISE EXCEPTION 'FAIL: revoked an unknown schema';
EXCEPTION WHEN invalid_parameter_value THEN
    IF SQLERRM NOT LIKE 'unknown schema%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: revoke refused an unknown schema';
END $$;

--- The actor is checked first: a non-admin learns nothing about which
--- schemas exist.
DO $$
BEGIN
    PERFORM auth.admin_set_user_permission('alice', 'alice', 'atlantis', 'read_only');
    RAISE EXCEPTION 'FAIL: non-admin reached the schema check';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: actor checked before schema';
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
    PERFORM auth.add_user_key('dave', 'laptop', encode(sha256('pk-dave-early'), 'base64'));
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
    IF NOT auth.add_user_key('dave', 'laptop', encode(sha256('pk-dave-laptop'), 'base64')) THEN
        RAISE EXCEPTION 'FAIL: activated dave could not add a key';
    END IF;
    IF auth.get_user_by_key(encode(sha256('pk-dave-laptop'), 'base64')) IS DISTINCT FROM 'dave' THEN
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
SELECT auth.add_user_key('alice', 'laptop', encode(sha256('pk-alice-laptop'), 'base64'));
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
    IF auth.get_user_by_key(encode(sha256('pk-alice-laptop'), 'base64')) IS DISTINCT FROM 'alice' THEN
        RAISE EXCEPTION 'FAIL: alice key stopped working';
    END IF;
    RAISE NOTICE 'ok: the sweep spares established users';
END $$;

--- Still provisional, so still no new keys, even with a working old one.
DO $$
BEGIN
    PERFORM auth.add_user_key('alice', 'desktop', encode(sha256('pk-alice-desktop'), 'base64'));
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
SELECT auth.add_user_key('carol', 'old', encode(sha256('pk-carol-old'), 'base64'));
SELECT auth.revoke_user_key('carol', 'old');
SELECT auth.add_user_key('carol', 'laptop', encode(sha256('pk-carol-laptop'), 'base64'));
SELECT auth.add_user_key('carol', 'intruder', encode(sha256('pk-carol-intruder'), 'base64'));
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
    IF auth.get_user_by_key(encode(sha256('pk-carol-laptop'), 'base64')) IS NOT NULL
       OR auth.get_user_by_key(encode(sha256('pk-carol-intruder'), 'base64')) IS NOT NULL THEN
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
    IF auth.get_user_by_key(encode(sha256('pk-dave-laptop'), 'base64')) IS DISTINCT FROM 'dave'
       OR auth.get_user_by_key(encode(sha256('pk-alice-laptop'), 'base64')) IS DISTINCT FROM 'alice' THEN
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
EXCEPTION WHEN object_in_use THEN
    IF SQLERRM NOT LIKE 'refusing%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: refused to demote the last admin';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_remove_user('root', 'root');
    RAISE EXCEPTION 'FAIL: the last admin deleted themselves';
EXCEPTION WHEN object_in_use THEN
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
EXCEPTION WHEN object_in_use THEN
    IF SQLERRM NOT LIKE 'refusing%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: refused to reset the last admin';
END $$;

DO $$
BEGIN
    PERFORM auth.admin_reset_user_password('root', 'root', 'hash-reset',
                                           INTERVAL '1 hour', TRUE);
    RAISE EXCEPTION 'FAIL: the last admin compromise-reset themselves';
EXCEPTION WHEN object_in_use THEN
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
SELECT auth.add_user_key('gone', 'laptop', encode(sha256('pk-gone'), 'base64'));
SELECT auth.admin_set_user_permission('root', 'gone', 'forge', 'read_only');

DO $$
BEGIN
    IF NOT auth.admin_remove_user('root', 'GONE') THEN
        RAISE EXCEPTION 'FAIL: could not remove gone';
    END IF;
    IF auth.get_user_by_key(encode(sha256('pk-gone'), 'base64')) IS NOT NULL THEN
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
---                     Single-use login assertions                     ---
--------------------------------------------------------------------------
--- dave and alice hold active keys; carol's were revoked by the
--- compromised reset above.

DO $$
BEGIN
    IF NOT auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-1',
                                  NOW() + INTERVAL '30 seconds') THEN
        RAISE EXCEPTION 'FAIL: a fresh assertion was refused';
    END IF;
    IF auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-1',
                              NOW() + INTERVAL '30 seconds') THEN
        RAISE EXCEPTION 'FAIL: a replayed assertion was accepted';
    END IF;
    --- The exp is not part of the identity: a replay with a new exp is
    --- still a replay.
    IF auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-1',
                              NOW() + INTERVAL '45 seconds') THEN
        RAISE EXCEPTION 'FAIL: a replay with a different exp was accepted';
    END IF;
    IF NOT auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-2',
                                  NOW() + INTERVAL '30 seconds') THEN
        RAISE EXCEPTION 'FAIL: a second assertion from dave was refused';
    END IF;
    --- Scoped per key: alice reusing dave's jti is not a replay.
    IF NOT auth.consume_assertion(encode(sha256('pk-alice-laptop'), 'base64'), 'jti-1',
                                  NOW() + INTERVAL '30 seconds') THEN
        RAISE EXCEPTION 'FAIL: one key''s jti blocked another key';
    END IF;
    RAISE NOTICE 'ok: each assertion logs in once';
END $$;

DO $$
BEGIN
    IF auth.consume_assertion(encode(sha256('pk-nobody'), 'base64'), 'jti-x',
                              NOW() + INTERVAL '30 seconds') THEN
        RAISE EXCEPTION 'FAIL: consumed an assertion for an unknown key';
    END IF;
    IF auth.consume_assertion(encode(sha256('pk-carol-laptop'), 'base64'), 'jti-x',
                              NOW() + INTERVAL '30 seconds') THEN
        RAISE EXCEPTION 'FAIL: consumed an assertion for a revoked key';
    END IF;
    RAISE NOTICE 'ok: only active keys consume assertions';
END $$;

DO $$
BEGIN
    IF auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-old',
                              NOW() - INTERVAL '1 second') THEN
        RAISE EXCEPTION 'FAIL: consumed an expired assertion';
    END IF;
    IF auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-now', NOW()) THEN
        RAISE EXCEPTION 'FAIL: consumed an assertion expiring now';
    END IF;
    IF auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-far',
                              NOW() + INTERVAL '6 minutes') THEN
        RAISE EXCEPTION 'FAIL: consumed an assertion with a far-future exp';
    END IF;
    IF auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), '',
                              NOW() + INTERVAL '30 seconds')
       OR auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), NULL,
                                 NOW() + INTERVAL '30 seconds')
       OR auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), repeat('j', 129),
                                 NOW() + INTERVAL '30 seconds')
       OR auth.consume_assertion(NULL, 'jti-x',
                                 NOW() + INTERVAL '30 seconds')
       OR auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-x', NULL) THEN
        RAISE EXCEPTION 'FAIL: consumed an assertion with bad inputs';
    END IF;
    IF NOT auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), repeat('j', 128),
                                  NOW() + INTERVAL '30 seconds') THEN
        RAISE EXCEPTION 'FAIL: refused a 128-character jti';
    END IF;
    RAISE NOTICE 'ok: consume_assertion rejects bad inputs';
END $$;

--- Expiry, in separate statements because NOW() is frozen per
--- transaction.  Once an assertion has expired its jti may be
--- forgotten, which is safe only because the expired assertion itself
--- can no longer be consumed.
SELECT auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-short',
                              NOW() + INTERVAL '1 second');
SELECT pg_sleep(1.5);

DO $$
BEGIN
    --- Triggers the cleanup of jti-short's row...
    IF NOT auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-3',
                                  NOW() + INTERVAL '30 seconds') THEN
        RAISE EXCEPTION 'FAIL: a fresh assertion was refused after expiry';
    END IF;
    --- ...and replaying the expired assertion with its own exp still fails.
    IF auth.consume_assertion(encode(sha256('pk-dave-laptop'), 'base64'), 'jti-short',
                              NOW() - INTERVAL '0.5 seconds') THEN
        RAISE EXCEPTION 'FAIL: an expired assertion was replayed';
    END IF;
    RAISE NOTICE 'ok: forgetting expired jtis reopens nothing';
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

--------------------------------------------------------------------------
---                          Key validation                             ---
--------------------------------------------------------------------------
--- A key the backend could never verify, or never fingerprint, would
--- sit in the table and break every listing that included it.

SELECT auth.admin_add_user('root', 'lister', 'hash-lister');

DO $$
DECLARE v_key TEXT := encode(sha256('pk-lister-shape'), 'base64');
BEGIN
    IF auth.add_user_key('lister', 'garbage', 'not base64!') THEN
        RAISE EXCEPTION 'FAIL: registered a key that is not base64';
    END IF;
    IF auth.add_user_key('lister', 'short',
                         encode(substr(sha256('pk-x'), 1, 31), 'base64')) THEN
        RAISE EXCEPTION 'FAIL: registered a 31-byte ed25519 key';
    END IF;
    IF auth.add_user_key('lister', 'long',
                         encode(sha256('pk-x') || '\x00'::bytea, 'base64')) THEN
        RAISE EXCEPTION 'FAIL: registered a 33-byte ed25519 key';
    END IF;
    --- The same 32 bytes spelled differently must not get past UNIQUE.
    IF auth.add_user_key('lister', 'unpadded', rtrim(v_key, '=')) THEN
        RAISE EXCEPTION 'FAIL: registered an unpadded key';
    END IF;
    IF auth.add_user_key('lister', 'wrapped',
                         substr(v_key, 1, 20) || E'\n' || substr(v_key, 21)) THEN
        RAISE EXCEPTION 'FAIL: registered a key with a newline inside it';
    END IF;
    IF auth.add_user_key('lister', 'rsa', v_key, 'rsa') THEN
        RAISE EXCEPTION 'FAIL: registered a key for an unsupported algorithm';
    END IF;
    IF auth.add_user_key('lister', 'stale', v_key, 'ed25519',
                         NOW() - INTERVAL '1 second')
       OR auth.add_user_key('lister', 'stale', v_key, 'ed25519', NOW()) THEN
        RAISE EXCEPTION 'FAIL: registered a key that had already expired';
    END IF;
    IF EXISTS (SELECT 1 FROM auth.list_user_keys('lister')) THEN
        RAISE EXCEPTION 'FAIL: a refused key left a row';
    END IF;
    --- Surrounding spaces are trimmed, as everywhere else.
    IF NOT auth.add_user_key('lister', 'shape', ' ' || v_key || ' ', 'ED25519') THEN
        RAISE EXCEPTION 'FAIL: refused a well-formed key';
    END IF;
    IF auth.get_user_by_key(v_key) IS DISTINCT FROM 'lister' THEN
        RAISE EXCEPTION 'FAIL: the well-formed key does not resolve';
    END IF;
    RAISE NOTICE 'ok: only verifiable keys are registered';
END $$;

--- The fingerprint is pinned to an outside computation, so a change of
--- encoding here is caught rather than silently agreeing with itself.
--- The key is RFC 8032's first ed25519 test vector; the fingerprint was
--- computed with Python's hashlib and base64.
DO $$
BEGIN
    IF NOT auth.add_user_key('lister', 'rfc8032',
                             '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=') THEN
        RAISE EXCEPTION 'FAIL: could not register the RFC 8032 key';
    END IF;
    IF (SELECT fingerprint FROM auth.list_user_keys('lister')
         WHERE key_name = 'rfc8032')
       IS DISTINCT FROM 'SHA256:If4x36FUomFia/hUBG/SJxt77UtqvkWqWId+9H+XIbk' THEN
        RAISE EXCEPTION 'FAIL: unexpected fingerprint %',
            (SELECT fingerprint FROM auth.list_user_keys('lister')
              WHERE key_name = 'rfc8032');
    END IF;
    RAISE NOTICE 'ok: the fingerprint matches an outside computation';
END $$;

--------------------------------------------------------------------------
---                        Key states                                   ---
--------------------------------------------------------------------------
--- Five ways a key can stand, set up across statements because NOW()
--- is frozen per transaction:
---   shape    active, no expiry (above)
---   live     active, expires in an hour
---   dated    expired, never revoked
---   pulled   revoked before its expiry
---   lapsed   expired, THEN revoked: it stopped at its expiry

SELECT auth.add_user_key('lister', 'live', encode(sha256('pk-lister-live'), 'base64'),
                         'ed25519', NOW() + INTERVAL '1 hour');
SELECT auth.add_user_key('lister', 'dated', encode(sha256('pk-lister-dated'), 'base64'),
                         'ed25519', NOW() + INTERVAL '1 second');
SELECT auth.add_user_key('lister', 'pulled', encode(sha256('pk-lister-pulled'), 'base64'),
                         'ed25519', NOW() + INTERVAL '1 hour');
SELECT auth.add_user_key('lister', 'lapsed', encode(sha256('pk-lister-lapsed'), 'base64'),
                         'ed25519', NOW() + INTERVAL '1 second');
SELECT auth.revoke_user_key('lister', 'pulled');
SELECT pg_sleep(1.5);
SELECT auth.revoke_user_key('lister', 'lapsed');

DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN SELECT * FROM auth.list_user_keys('lister') LOOP
        CASE r.key_name
        WHEN 'shape', 'rfc8032', 'live' THEN
            IF NOT r.active OR r.invalidated IS NOT NULL
               OR r.reason IS NOT NULL THEN
                RAISE EXCEPTION 'FAIL: % should be active: %', r.key_name, r;
            END IF;
        WHEN 'dated' THEN
            IF r.active OR r.reason IS DISTINCT FROM 'expired'
               OR r.invalidated IS DISTINCT FROM r.expires
               OR r.revoked IS NOT NULL THEN
                RAISE EXCEPTION 'FAIL: dated should be expired: %', r;
            END IF;
        WHEN 'pulled' THEN
            IF r.active OR r.reason IS DISTINCT FROM 'revoked'
               OR r.invalidated IS DISTINCT FROM r.revoked THEN
                RAISE EXCEPTION 'FAIL: pulled should be revoked: %', r;
            END IF;
        WHEN 'lapsed' THEN
            IF r.active OR r.reason IS DISTINCT FROM 'expired'
               OR r.invalidated IS DISTINCT FROM r.expires
               OR r.revoked IS NULL OR r.revoked <= r.expires THEN
                RAISE EXCEPTION 'FAIL: lapsed should have expired first: %', r;
            END IF;
        ELSE
            RAISE EXCEPTION 'FAIL: unexpected key %', r.key_name;
        END CASE;
        IF r.fingerprint IS NULL OR r.fingerprint NOT LIKE 'SHA256:%' THEN
            RAISE EXCEPTION 'FAIL: % has no fingerprint', r.key_name;
        END IF;
    END LOOP;
    IF (SELECT count(*) FROM auth.list_user_keys('lister')) <> 6 THEN
        RAISE EXCEPTION 'FAIL: expected six lister keys';
    END IF;
    --- The listing and the login agree on what active means.
    IF auth.get_user_by_key(encode(sha256('pk-lister-live'), 'base64'))
           IS DISTINCT FROM 'lister'
       OR auth.get_user_by_key(encode(sha256('pk-lister-dated'), 'base64'))
           IS NOT NULL
       OR auth.get_user_by_key(encode(sha256('pk-lister-pulled'), 'base64'))
           IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: login disagrees with the listing';
    END IF;
    RAISE NOTICE 'ok: key states';
END $$;

--------------------------------------------------------------------------
---                      Administrative listings                        ---
--------------------------------------------------------------------------
--- State at this point: root (admin), alice and dave (active), carol
--- (reset after a compromise, so provisional), lister (active, keys
--- above).  Add a new provisional user and one whose window lapses.

SELECT auth.admin_set_user_permission('root', 'lister', 'ynp', 'read_write');
SELECT auth.admin_set_user_permission('root', 'lister', 'utah', 'read_only');
SELECT auth.admin_add_provisional_user('root', 'newbie', 'hash-newbie',
                                       INTERVAL '1 hour');
SELECT auth.admin_set_user_admin('root', 'newbie', TRUE);
SELECT auth.admin_add_provisional_user('root', 'tardy', 'hash-tardy',
                                       INTERVAL '1 second');
SELECT pg_sleep(1.5);

DO $$
DECLARE r RECORD;
BEGIN
    IF (SELECT array_agg(name) FROM auth.admin_list_users('root'))
       IS DISTINCT FROM ARRAY['alice', 'carol', 'dave', 'lister', 'newbie',
                              'root', 'tardy'] THEN
        RAISE EXCEPTION 'FAIL: unexpected users or order: %',
            (SELECT array_agg(name) FROM auth.admin_list_users('root'));
    END IF;
    FOR r IN SELECT * FROM auth.admin_list_users('ROOT') LOOP
        IF r.created IS NULL OR r.password_updated IS NULL THEN
            RAISE EXCEPTION 'FAIL: % missing a timestamp: %', r.name, r;
        END IF;
        CASE r.name
        WHEN 'root' THEN
            IF NOT r.is_admin OR r.provisional_until IS NOT NULL
               OR r.expired OR r.password_reset THEN
                RAISE EXCEPTION 'FAIL: root: %', r;
            END IF;
        WHEN 'alice' THEN
            --- The only one record_login has been called for.
            IF r.is_admin OR r.provisional_until IS NOT NULL
               OR r.last_login IS NULL OR r.expired OR r.password_reset THEN
                RAISE EXCEPTION 'FAIL: alice: %', r;
            END IF;
        WHEN 'carol' THEN
            IF r.provisional_until IS NULL OR r.expired
               OR NOT r.password_reset THEN
                RAISE EXCEPTION 'FAIL: carol should be a live reset: %', r;
            END IF;
        WHEN 'newbie' THEN
            IF NOT r.is_admin OR r.provisional_until IS NULL OR r.expired
               OR r.password_reset OR r.last_login IS NOT NULL THEN
                RAISE EXCEPTION 'FAIL: newbie should be a new pending admin: %', r;
            END IF;
        WHEN 'tardy' THEN
            IF r.provisional_until IS NULL OR NOT r.expired
               OR r.password_reset THEN
                RAISE EXCEPTION 'FAIL: tardy should have lapsed: %', r;
            END IF;
        ELSE
            IF r.provisional_until IS NOT NULL OR r.expired
               OR r.password_reset THEN
                RAISE EXCEPTION 'FAIL: % should be active: %', r.name, r;
            END IF;
        END CASE;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_proc p
                 JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'auth' AND p.proname LIKE 'admin_list_%'
                  AND ('password_hash' = ANY(p.proargnames)
                       OR 'public_key' = ANY(p.proargnames))) THEN
        RAISE EXCEPTION 'FAIL: an admin listing exposes a hash or a raw key';
    END IF;
    RAISE NOTICE 'ok: admin_list_users';
END $$;

DO $$
BEGIN
    IF (SELECT array_agg(ROW(schema_name, permission_name)::TEXT)
          FROM auth.admin_list_permissions('root') WHERE name = 'lister')
       IS DISTINCT FROM ARRAY['(utah,read_only)', '(ynp,read_write)'] THEN
        RAISE EXCEPTION 'FAIL: unexpected lister grants: %',
            (SELECT array_agg(ROW(schema_name, permission_name)::TEXT)
               FROM auth.admin_list_permissions('root') WHERE name = 'lister');
    END IF;
    IF EXISTS (SELECT 1 FROM auth.admin_list_permissions('root')
                WHERE granted IS NULL) THEN
        RAISE EXCEPTION 'FAIL: a grant has no time';
    END IF;
    --- Sorted by name, then schema.
    IF (SELECT array_agg(name || '/' || schema_name)
          FROM auth.admin_list_permissions('root'))
       IS DISTINCT FROM
       (SELECT array_agg(name || '/' || schema_name ORDER BY name, schema_name)
          FROM auth.admin_list_permissions('root')) THEN
        RAISE EXCEPTION 'FAIL: permissions not sorted';
    END IF;
    RAISE NOTICE 'ok: admin_list_permissions';
END $$;

DO $$
BEGIN
    --- The admin view is the same rows as the user's own view.
    IF EXISTS (
        (SELECT key_name, algorithm, fingerprint, created, expires, revoked,
                last_used, active, invalidated, reason
           FROM auth.admin_list_keys('root') WHERE name = 'lister')
        EXCEPT ALL
        (SELECT * FROM auth.list_user_keys('lister'))) THEN
        RAISE EXCEPTION 'FAIL: admin and user key listings disagree';
    END IF;
    IF (SELECT count(*) FROM auth.admin_list_keys('root')
         WHERE name = 'lister') <> 6 THEN
        RAISE EXCEPTION 'FAIL: admin listing lost lister keys';
    END IF;
    --- carol's three, all revoked by the compromise reset.
    IF (SELECT array_agg(reason) FROM auth.admin_list_keys('root')
         WHERE name = 'carol')
       IS DISTINCT FROM ARRAY['revoked', 'revoked', 'revoked'] THEN
        RAISE EXCEPTION 'FAIL: carol keys should read revoked';
    END IF;
    RAISE NOTICE 'ok: admin_list_keys';
END $$;

--- Only an activated administrator may list.  Each call in its own
--- block: a raise aborts the rest of a block.
DO $$
DECLARE v_call TEXT;
        v_actor TEXT;
BEGIN
    FOREACH v_actor IN ARRAY ARRAY['dave', 'newbie', 'nobody', ''] LOOP
        FOREACH v_call IN ARRAY ARRAY['admin_list_users',
                                      'admin_list_permissions',
                                      'admin_list_keys'] LOOP
            BEGIN
                EXECUTE format('SELECT * FROM auth.%I($1)', v_call)
                  USING v_actor;
                RAISE EXCEPTION 'FAIL: % listed via %', v_actor, v_call;
            EXCEPTION WHEN insufficient_privilege THEN
                IF SQLERRM NOT LIKE 'not authorized%' THEN RAISE; END IF;
            END;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'ok: only an activated administrator may list';
END $$;

--- The unfiltered key table behind the listings is not the backend's
--- to call.
DO $$
BEGIN
    PERFORM * FROM auth.key_states();
    RAISE EXCEPTION 'FAIL: writer could call key_states';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM NOT LIKE 'permission denied%' THEN RAISE; END IF;
    RAISE NOTICE 'ok: writer denied key_states';
END $$;

--- Leave the user set the reader suite expects.
SELECT auth.admin_remove_user('root', 'newbie');
SELECT auth.admin_remove_user('root', 'tardy');

\echo 'testAuthWriter.sql: ALL PASSED'
