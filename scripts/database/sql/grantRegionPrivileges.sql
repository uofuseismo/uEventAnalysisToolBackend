--- Purpose: Grants privileges for one region (or sandbox) schema.
--- Driven by create.sh with -v target_schema=<schema>, after
--- createRegionCore.sql and the region extension file.  Also expects
--- rw_role and ro_role.
---
--- Philosophy:
---   * Reads are open: promoted columns exist precisely so people can
---     run ad hoc SELECTs, so both roles get SELECT on tables.
---   * Writes to events are function-only.  Nobody holds direct
---     INSERT/UPDATE/DELETE, so seed_event/publish_event (and their
---     tripwires) cannot be bypassed.
---   * event_history is writable by no role at all.  The archive
---     trigger runs as SECURITY DEFINER, so append happens without
---     the caller holding any history privilege.  History SELECT is
---     read_write only (superseded blobs may hold pre-review data).
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

SET search_path TO :"target_schema";

GRANT USAGE ON SCHEMA :"target_schema"
    TO :"rw_role", :"ro_role";

--- Kill the EXECUTE-to-PUBLIC default on everything here.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA :"target_schema" FROM PUBLIC;

--- Reads: open to both roles, current-state table only.
GRANT SELECT ON events TO :"rw_role", :"ro_role";
GRANT SELECT ON event_history TO :"rw_role";

--- Writes: function-only.  The functions and the archive trigger run
--- as their owner, so callers need no table privileges at all.
ALTER FUNCTION seed_event(TEXT, JSONB) SECURITY DEFINER;
ALTER FUNCTION publish_event(TEXT, JSONB) SECURITY DEFINER;
ALTER FUNCTION archive_event() SECURITY DEFINER;
--- (search_path already pinned FROM CURRENT at creation.)

GRANT EXECUTE ON FUNCTION seed_event(TEXT, JSONB) TO :"rw_role";
GRANT EXECUTE ON FUNCTION publish_event(TEXT, JSONB) TO :"rw_role";
GRANT EXECUTE ON FUNCTION get_event(TEXT)
    TO :"rw_role", :"ro_role";

--- Future tables added by region extension files: hand out SELECT
--- automatically so read paths keep working without editing this
--- file.  Write grants stay a deliberate, per-table decision.
ALTER DEFAULT PRIVILEGES IN SCHEMA :"target_schema"
    GRANT SELECT ON TABLES TO :"rw_role", :"ro_role";

RESET search_path;
