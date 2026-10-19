--- Purpose: Defines application-level authorization: which frontend
--- users can do what in which schema.  The backend consults these
--- tables (via the functions below) on every authorization check.
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

--- The schemas a user can be granted access to.  Kept as a table so a
--- typo'd schema name can't be inserted, and new regions are one INSERT.
DROP TABLE IF EXISTS auth.schemas CASCADE;
CREATE TABLE auth.schemas(
    schema_id SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    schema_name TEXT UNIQUE NOT NULL CHECK (schema_name = lower(schema_name))
);
INSERT INTO auth.schemas (schema_name)
    VALUES ('utah'),  ('sandbox_utah'),
           ('ynp'),   ('sandbox_ynp'),
           ('forge'), ('sandbox_forge'),
           ('external');

--- The permission levels.  New levels (e.g., management) are one
--- INSERT away.
DROP TABLE IF EXISTS auth.permissions CASCADE;
CREATE TABLE auth.permissions(
    permission_id SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    permission_name TEXT UNIQUE NOT NULL
        CHECK (permission_name = lower(permission_name)),
    description TEXT
);
INSERT INTO auth.permissions (permission_name, description)
    VALUES ('read_only',  'Can view data in the schema'),
           ('read_write', 'Can view and modify data in the schema');

--- Maps users to (schema, permission).  One permission per user per
--- schema; upgrading a user is an UPDATE, not a second row.
DROP TABLE IF EXISTS auth.user_schema_permissions CASCADE;
CREATE TABLE auth.user_schema_permissions(
    user_id BIGINT NOT NULL
        REFERENCES auth.users(user_id) ON DELETE CASCADE,
    schema_id SMALLINT NOT NULL
        REFERENCES auth.schemas(schema_id) ON DELETE CASCADE,
    permission_id SMALLINT NOT NULL
        REFERENCES auth.permissions(permission_id),
    granted TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, schema_id)
);

--- Grants (or updates) a user's permission on a schema.
--- Returns FALSE if the user, schema, or permission doesn't exist.
--- Ungated and granted to no role; the backend calls
--- auth.admin_set_user_permission.
CREATE OR REPLACE FUNCTION auth.set_user_permission(
    p_name TEXT, p_schema TEXT, p_permission TEXT)
RETURNS BOOLEAN AS $$
DECLARE v_user_id BIGINT;
        v_schema_id SMALLINT;
        v_permission_id SMALLINT;
BEGIN
    SELECT user_id INTO v_user_id
      FROM auth.users WHERE name = lower(trim(p_name));
    SELECT schema_id INTO v_schema_id
      FROM auth.schemas WHERE schema_name = lower(trim(p_schema));
    SELECT permission_id INTO v_permission_id
      FROM auth.permissions WHERE permission_name = lower(trim(p_permission));
    IF v_user_id IS NULL OR v_schema_id IS NULL OR v_permission_id IS NULL THEN
        RETURN FALSE;
    END IF;
    INSERT INTO auth.user_schema_permissions (user_id, schema_id, permission_id)
        VALUES (v_user_id, v_schema_id, v_permission_id)
        ON CONFLICT (user_id, schema_id)
        DO UPDATE SET permission_id = EXCLUDED.permission_id,
                      granted = NOW();
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

--- Revokes a user's permission on a schema.  Returns TRUE if a row
--- was deleted.  Ungated and granted to no role; the backend calls
--- auth.admin_revoke_user_permission.
CREATE OR REPLACE FUNCTION auth.revoke_user_permission(
    p_name TEXT, p_schema TEXT)
RETURNS BOOLEAN AS $$
DECLARE n_deleted INTEGER;
BEGIN
    DELETE FROM auth.user_schema_permissions usp
     USING auth.users u, auth.schemas s
     WHERE usp.user_id = u.user_id
       AND usp.schema_id = s.schema_id
       AND u.name = lower(trim(p_name))
       AND s.schema_name = lower(trim(p_schema));
    GET DIAGNOSTICS n_deleted = ROW_COUNT;
    RETURN n_deleted > 0;
END;
$$ LANGUAGE plpgsql;

--- The workhorse: what can this user do in this schema?
--- Returns the permission name, or NULL if none.
CREATE OR REPLACE FUNCTION auth.get_user_permission(p_name TEXT, p_schema TEXT)
RETURNS TEXT AS $$
    SELECT p.permission_name
      FROM auth.user_schema_permissions usp
      JOIN auth.users u ON u.user_id = usp.user_id
      JOIN auth.schemas s ON s.schema_id = usp.schema_id
      JOIN auth.permissions p ON p.permission_id = usp.permission_id
     WHERE u.name = lower(trim(p_name))
       AND s.schema_name = lower(trim(p_schema));
$$ LANGUAGE sql;

--- Lists the schemas a user can access and at what level.
--- The frontend's region selector is built from this.
CREATE OR REPLACE FUNCTION auth.list_user_schemas(p_name TEXT)
RETURNS TABLE(schema_name TEXT, permission_name TEXT) AS $$
    SELECT s.schema_name, p.permission_name
      FROM auth.user_schema_permissions usp
      JOIN auth.users u ON u.user_id = usp.user_id
      JOIN auth.schemas s ON s.schema_id = usp.schema_id
      JOIN auth.permissions p ON p.permission_id = usp.permission_id
     WHERE u.name = lower(trim(p_name))
     ORDER BY s.schema_name;
$$ LANGUAGE sql;
