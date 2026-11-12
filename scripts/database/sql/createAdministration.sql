--- Purpose: User administration.  Every admin_ function takes p_actor:
--- the logged-in user on whose behalf the backend is acting.  The
--- check happens here rather than in the backend for the same reason
--- password hashes are unreachable there -- the database should not
--- depend on the backend being correct.  It also closes the gap left
--- by bearer tokens: a demoted administrator's token may still claim
--- admin for a few minutes, but the database asks the users table.
---
--- The grant says which BACKEND may ask; the actor says on whose
--- behalf.  Both have to hold.
---
--- Authorization failure RAISEs insufficient_privilege (SQLSTATE 42501)
--- instead of returning FALSE.  A boolean cannot distinguish 'you may
--- not' from 'that did not work', and those are PERMISSION_DENIED and
--- INVALID_ARGUMENT to the frontend.  The other refusals the backend
--- must tell apart get SQLSTATEs of their own:
---     55006 object_in_use            this would leave no administrator
---     22023 invalid_parameter_value  no such schema
---     42704 undefined_object         no such permission level (the
---                                    backend sends an enum, so this is
---                                    a deployment bug, not user input)
--- Anything else that is wrong (no such user, nothing to revoke)
--- returns FALSE.
---
--- Runs after createUsersTable.sql and createPermissionsTables.sql;
--- it wraps functions from both.
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

--------------------------------------------------------------------------
---                         Who is an admin                             ---
--------------------------------------------------------------------------

--- TRUE if this user is an activated administrator.  An administrator
--- holding an issued password is not one yet: they have proved only
--- that they received it.  The frontend may use this to decide whether
--- to show user management at all; the functions below do not trust
--- that decision.
CREATE OR REPLACE FUNCTION auth.user_is_admin(p_name TEXT)
RETURNS BOOLEAN AS $$
    SELECT COALESCE(
        (SELECT is_admin AND provisional_until IS NULL
           FROM auth.users WHERE name = lower(trim(p_name))),
        FALSE);
$$ LANGUAGE sql;

--- Raises unless p_actor is an activated administrator.  Granted to no
--- role: it runs from inside the definer functions below.
CREATE OR REPLACE FUNCTION auth.require_admin(p_actor TEXT)
RETURNS VOID AS $$
BEGIN
    --- One message for every failure: whether a given name exists is
    --- not something an unauthorized caller should be able to probe.
    IF NOT auth.user_is_admin(p_actor) THEN
        RAISE EXCEPTION 'not authorized: administrator privilege required'
              USING ERRCODE = 'insufficient_privilege';
    END IF;
END;
$$ LANGUAGE plpgsql;

--- How many administrators can actually administer right now.
--- Takes no locks, so the answer is stale on arrival.  Fine for
--- display; NOT the basis for deciding whether an administrator may be
--- removed -- see auth.forbid_last_admin_removal.
CREATE OR REPLACE FUNCTION auth.count_active_admins()
RETURNS INTEGER AS $$
    SELECT count(*)::INTEGER FROM auth.users
     WHERE is_admin AND provisional_until IS NULL;
$$ LANGUAGE sql;

--- Raises if p_name is the last activated administrator.  Called before
--- anything that would demote, delete, or de-activate one; without it
--- the database is one ordinary-looking call away from being locked out
--- of its own user management, with a superuser session the only way
--- back in.
---
--- The FOR UPDATE is the point of this function.  Counting first and
--- removing second is safe only if nothing removes an administrator in
--- between, and two administrators on two browsers are exactly that:
--- each counts two, each removes the other, both commit, nobody is
--- left.  That is write skew, which REPEATABLE READ permits just as
--- READ COMMITTED does.  Locking EVERY activated administrator row,
--- not just the target, makes the second caller block on a row the
--- first holds; when it wakes it re-reads, sees the new count, and
--- refuses -- at the default isolation level, with no retry loop.
---
--- SERIALIZABLE would also close it, but cannot be set from inside a
--- function, so every caller would have to remember to impose it and
--- then replay serialization failures.  A lock the function takes for
--- itself cannot be forgotten by a caller.
---
--- ORDER BY name so concurrent callers lock in one order and cannot
--- deadlock against each other.
CREATE OR REPLACE FUNCTION auth.forbid_last_admin_removal(p_name TEXT)
RETURNS VOID AS $$
DECLARE n_admins INTEGER;
BEGIN
    IF NOT auth.user_is_admin(p_name) THEN
        RETURN;
    END IF;
    SELECT count(*) INTO n_admins
      FROM (SELECT 1 FROM auth.users
             WHERE is_admin AND provisional_until IS NULL
             ORDER BY name
               FOR UPDATE) locked_admins;
    IF n_admins <= 1 THEN
        RAISE EXCEPTION 'refusing to leave the database with no administrator'
              USING ERRCODE = 'object_in_use';
    END IF;
END;
$$ LANGUAGE plpgsql;

--------------------------------------------------------------------------
---                         Creating users                              ---
--------------------------------------------------------------------------
--- Neither creates an administrator; promote afterwards with
--- auth.admin_set_user_admin.  One way to make an admin, not three.

--- Creates a user with a password the administrator chose.  Prefer
--- auth.admin_add_provisional_user: it does not leave an administrator
--- holding a working credential for someone else's account.
CREATE OR REPLACE FUNCTION auth.admin_add_user(
    p_actor TEXT, p_name TEXT, p_password_hash TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    PERFORM auth.require_admin(p_actor);
    RETURN auth.add_user(p_name, p_password_hash, FALSE);
END;
$$ LANGUAGE plpgsql;

--- The normal way to add someone: an issued password valid for
--- p_valid_for, handed over out of band.  The account deletes itself
--- if they never replace it.
CREATE OR REPLACE FUNCTION auth.admin_add_provisional_user(
    p_actor TEXT, p_name TEXT, p_password_hash TEXT, p_valid_for INTERVAL)
RETURNS BOOLEAN AS $$
BEGIN
    PERFORM auth.require_admin(p_actor);
    RETURN auth.add_provisional_user(p_name, p_password_hash, p_valid_for);
END;
$$ LANGUAGE plpgsql;

--------------------------------------------------------------------------
---                         Changing users                              ---
--------------------------------------------------------------------------

--- Grants or removes administrator.  Returns FALSE if there is no such
--- user or p_is_admin is NULL.
CREATE OR REPLACE FUNCTION auth.admin_set_user_admin(
    p_actor TEXT, p_name TEXT, p_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
DECLARE n_updated INTEGER;
BEGIN
    PERFORM auth.require_admin(p_actor);
    IF p_is_admin IS NULL THEN
        RETURN FALSE;
    END IF;
    --- Demoting the last admin is the same lockout as deleting them,
    --- and demoting yourself by accident is the likelier version.
    IF NOT p_is_admin THEN
        PERFORM auth.forbid_last_admin_removal(p_name);
    END IF;
    UPDATE auth.users
       SET is_admin = p_is_admin
     WHERE name = lower(trim(p_name));
    GET DIAGNOSTICS n_updated = ROW_COUNT;
    RETURN n_updated > 0;
END;
$$ LANGUAGE plpgsql;

--- Grants (or changes) a user's permission on a schema.
CREATE OR REPLACE FUNCTION auth.admin_set_user_permission(
    p_actor TEXT, p_name TEXT, p_schema TEXT, p_permission TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    PERFORM auth.require_admin(p_actor);
    RETURN auth.set_user_permission(p_name, p_schema, p_permission);
END;
$$ LANGUAGE plpgsql;

--- Revokes a user's permission on a schema.
CREATE OR REPLACE FUNCTION auth.admin_revoke_user_permission(
    p_actor TEXT, p_name TEXT, p_schema TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    PERFORM auth.require_admin(p_actor);
    RETURN auth.revoke_user_permission(p_name, p_schema);
END;
$$ LANGUAGE plpgsql;

--- Resets a password.  The new password is issued, not chosen: the user
--- must replace it within p_valid_for, so the administrator is not left
--- holding a working credential for the account.  Returns FALSE if the
--- user does not exist or the inputs are bad.
---
--- p_revoke_keys has no default because the two reasons for a reset
--- want opposite things and the caller must say which this is:
---
---   FALSE  'I forgot my password.'  Keys keep working; nothing else
---          about the account changes.
---   TRUE   'This account is compromised.'  Every active key is
---          revoked as well, since an intruder holding the password
---          could have registered one.  The rows stay for audit.
---
--- Neither invalidates bearer tokens already issued; those die at
--- their expiry.
---
--- A reset makes the target provisional, and a provisional admin
--- cannot act -- so resetting the last administrator, including
--- yourself, is a lockout like any other and is refused.
CREATE OR REPLACE FUNCTION auth.admin_reset_user_password(
    p_actor TEXT, p_name TEXT, p_password_hash TEXT, p_valid_for INTERVAL,
    p_revoke_keys BOOLEAN)
RETURNS BOOLEAN AS $$
DECLARE v_user_id BIGINT;
BEGIN
    PERFORM auth.require_admin(p_actor);
    IF p_password_hash IS NULL OR length(p_password_hash) = 0 THEN
        RETURN FALSE;
    END IF;
    IF p_valid_for IS NULL OR p_valid_for <= INTERVAL '0' THEN
        RETURN FALSE;
    END IF;
    IF p_revoke_keys IS NULL THEN
        RETURN FALSE;
    END IF;
    PERFORM auth.forbid_last_admin_removal(p_name);
    UPDATE auth.users
       SET password_hash = p_password_hash,
           password_updated = NOW(),
           provisional_until = NOW() + p_valid_for
     WHERE name = lower(trim(p_name))
    RETURNING user_id INTO v_user_id;
    IF v_user_id IS NULL THEN
        RETURN FALSE;
    END IF;
    IF p_revoke_keys THEN
        UPDATE auth.user_keys
           SET revoked = NOW()
         WHERE user_id = v_user_id
           AND revoked IS NULL;
    END IF;
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

--- Deletes a user.  Their keys and permissions go with them.
CREATE OR REPLACE FUNCTION auth.admin_remove_user(p_actor TEXT, p_name TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    PERFORM auth.require_admin(p_actor);
    PERFORM auth.forbid_last_admin_removal(p_name);
    RETURN auth.remove_user(p_name);
END;
$$ LANGUAGE plpgsql;

--------------------------------------------------------------------------
---                          Listing users                              ---
--------------------------------------------------------------------------

--- There used to be an ungated auth.list_users() here, granted to both
--- backends.  It let the read-only backend enumerate every account --
--- names, who is an administrator, who holds an issued password -- which
--- is exactly what an attacker probing logins wants.  admin_list_users
--- replaced it; dropped so an upgraded database does not keep it.
DROP FUNCTION IF EXISTS auth.list_users();

--- The administrator's view: three listings, one row shape each, that
--- the backend stitches together by name.  Call all three in ONE
--- read-only REPEATABLE READ transaction -- each sees the same snapshot
--- and the same NOW(), so a user cannot vanish between the listings or
--- a key expire between two of them.  All are sorted by name.

--- Every user.  provisional_until is the backend's split: non-NULL is
--- a provisional user, whose remaining columns mean:
---   expired         TRUE if the issued password has lapsed; they are
---                   locked out until reset again.  Always FALSE for an
---                   active user.
---   password_reset  TRUE if they were active before (a reset), FALSE
---                   for a new user who never chose a password.  Always
---                   FALSE for an active user.
--- is_admin on a provisional user is authority they will have once
--- they activate, not authority they have now.
CREATE OR REPLACE FUNCTION auth.admin_list_users(p_actor TEXT)
RETURNS TABLE(name TEXT, is_admin BOOLEAN, created TIMESTAMPTZ,
              password_updated TIMESTAMPTZ, last_login TIMESTAMPTZ,
              provisional_until TIMESTAMPTZ, expired BOOLEAN,
              password_reset BOOLEAN) AS $$
BEGIN
    PERFORM auth.require_admin(p_actor);
    RETURN QUERY
        SELECT u.name, u.is_admin, u.created, u.password_updated,
               u.last_login, u.provisional_until,
               COALESCE(u.provisional_until <= NOW(), FALSE),
               u.provisional_until IS NOT NULL AND u.activated IS NOT NULL
          FROM auth.users u
         ORDER BY u.name;
END;
$$ LANGUAGE plpgsql;

--- Every grant.  granted is when the current level was set: upgrading
--- a user restamps it.
CREATE OR REPLACE FUNCTION auth.admin_list_permissions(p_actor TEXT)
RETURNS TABLE(name TEXT, schema_name TEXT, permission_name TEXT,
              granted TIMESTAMPTZ) AS $$
BEGIN
    PERFORM auth.require_admin(p_actor);
    RETURN QUERY
        SELECT u.name, s.schema_name, p.permission_name, usp.granted
          FROM auth.user_schema_permissions usp
          JOIN auth.users u ON u.user_id = usp.user_id
          JOIN auth.schemas s ON s.schema_id = usp.schema_id
          JOIN auth.permissions p ON p.permission_id = usp.permission_id
         ORDER BY u.name, s.schema_name;
END;
$$ LANGUAGE plpgsql;

--- Every key, active and not.  Same columns as auth.list_user_keys,
--- with the owner's name first; see auth.key_states for active,
--- invalidated, and reason.
CREATE OR REPLACE FUNCTION auth.admin_list_keys(p_actor TEXT)
RETURNS TABLE(name TEXT, key_name TEXT, algorithm TEXT, fingerprint TEXT,
              created TIMESTAMPTZ, expires TIMESTAMPTZ, revoked TIMESTAMPTZ,
              last_used TIMESTAMPTZ, active BOOLEAN,
              invalidated TIMESTAMPTZ, reason TEXT) AS $$
BEGIN
    PERFORM auth.require_admin(p_actor);
    RETURN QUERY
        SELECT u.name, k.key_name, k.algorithm, k.fingerprint, k.created,
               k.expires, k.revoked, k.last_used, k.active, k.invalidated,
               k.reason
          FROM auth.key_states() k
          JOIN auth.users u ON u.user_id = k.user_id
         ORDER BY u.name, k.created, k.key_name;
END;
$$ LANGUAGE plpgsql;
