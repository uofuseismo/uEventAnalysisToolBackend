--- Purpose: Creates a region (or sandbox) schema and its core tables.
--- Driven by create.sh with -v target_schema=<schema>.
---
--- Design notes:
---   * events.data (JSONB) is the source of truth.  Promoted columns
---     are GENERATED from the blob: always in sync, indexable, and
---     their casts double as type validation at insert time.
---   * origin_time in the blob is EPOCH SECONDS (double).  A direct
---     text->timestamptz cast is not immutable (it depends on session
---     timezone settings) so postgres forbids it in a generated
---     column; to_timestamp(double) is immutable and unambiguous.
---   * event_history is append-only.  A trigger archives the prior
---     blob on every UPDATE/DELETE, so the previous (e.g., automatic)
---     solution is always recoverable and the writer can't forget.
---   * seed_event (INSERT-only) and publish_event (UPDATE-only) are
---     deliberately not an upsert: a duplicate seed and a phantom
---     publish are different upstream failures and must fail loudly
---     and distinguishably.  This database does not mint event ids;
---     it only trips a wire when the naming service misbehaves.
--- Copyright: Ben Baker (UUSS) distributed under the MIT license.

DROP SCHEMA IF EXISTS :"target_schema" CASCADE;
CREATE SCHEMA :"target_schema";

--- Unqualified names below resolve to the target schema.  Functions
--- capture this at creation time via SET search_path FROM CURRENT,
--- so they remain bound to their own schema no matter who calls them.
SET search_path TO :"target_schema";

--------------------------------------------------------------------------
---                              Events                                 ---
--------------------------------------------------------------------------
CREATE TABLE events(
    --- Minted by the naming microservice; this database trusts it.
    event_id TEXT PRIMARY KEY CHECK (length(event_id) > 0),
    --- Everything we know about the event.  Source of truth.
    data JSONB NOT NULL,
    --- Lifecycle state.  The CHECK is a baked-in review: a blob
    --- claiming any other status bounces at insert, not next quarter.
    status TEXT NOT NULL GENERATED ALWAYS AS (data->>'status') STORED
        CHECK (status IN ('automatic', 'published', 'deleted')),
    --- Promoted fields for indexing/statistics.  The casts reject
    --- wrongly-typed values (e.g., "magnitude": "3.2 ML") at the door.
    origin_time TIMESTAMPTZ GENERATED ALWAYS AS
        (to_timestamp((data->>'origin_time')::double precision)) STORED,
    latitude DOUBLE PRECISION GENERATED ALWAYS AS
        ((data->>'latitude')::double precision) STORED
        CHECK (latitude BETWEEN -90 AND 90),
    longitude DOUBLE PRECISION GENERATED ALWAYS AS
        ((data->>'longitude')::double precision) STORED
        CHECK (longitude BETWEEN -180 AND 180),
    magnitude REAL GENERATED ALWAYS AS
        ((data->>'magnitude')::real) STORED,
    last_modified TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX events_origin_time_idx ON events(origin_time);
CREATE INDEX events_magnitude_idx   ON events(magnitude);
CREATE INDEX events_status_idx      ON events(status);
CREATE INDEX events_data_gin        ON events USING GIN (data);

--------------------------------------------------------------------------
---                          Event history                              ---
--------------------------------------------------------------------------
--- Append-only.  Holds every superseded blob (e.g., the automatic
--- solution after an analyst publishes over it).
CREATE TABLE event_history(
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id TEXT NOT NULL,
    data JSONB NOT NULL,
    replaced TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX event_history_event_id_idx ON event_history(event_id);

CREATE FUNCTION archive_event() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO event_history (event_id, data)
        VALUES (OLD.event_id, OLD.data);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SET search_path FROM CURRENT;

CREATE TRIGGER events_archive BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION archive_event();

--------------------------------------------------------------------------
---                         Write functions                             ---
--------------------------------------------------------------------------
--- Seeds a new event from the automatic system.  INSERT only.
--- Returns TRUE on success.  A duplicate id means the naming service
--- double-issued -- an upstream incident, surfaced as a WARNING plus
--- FALSE so the backend can alert on it distinctly.
CREATE FUNCTION seed_event(p_event_id TEXT, p_data JSONB)
RETURNS BOOLEAN AS $$
BEGIN
    IF p_event_id IS NULL OR length(trim(p_event_id)) = 0 THEN
        RETURN FALSE;
    END IF;
    INSERT INTO events (event_id, data)
        VALUES (trim(p_event_id), p_data);
    RETURN TRUE;
EXCEPTION WHEN unique_violation THEN
    RAISE WARNING 'duplicate event id % -- naming service issue?',
        p_event_id;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql SET search_path FROM CURRENT;

--- Publishes (or otherwise revises) an existing event.  UPDATE only.
--- Returns TRUE if the event existed.  A miss means someone is
--- reviewing an event that was never seeded -- a different problem.
--- The prior blob is archived automatically by the trigger.
CREATE FUNCTION publish_event(p_event_id TEXT, p_data JSONB)
RETURNS BOOLEAN AS $$
DECLARE n_updated INTEGER;
BEGIN
    UPDATE events
       SET data = p_data,
           last_modified = NOW()
     WHERE event_id = trim(p_event_id);
    GET DIAGNOSTICS n_updated = ROW_COUNT;
    RETURN n_updated > 0;
END;
$$ LANGUAGE plpgsql SET search_path FROM CURRENT;

--- Everything we know about an event.  The reader's workhorse.
CREATE FUNCTION get_event(p_event_id TEXT)
RETURNS JSONB AS $$
    SELECT data FROM events WHERE event_id = trim(p_event_id);
$$ LANGUAGE sql SET search_path FROM CURRENT;

RESET search_path;
