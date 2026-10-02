CREATE TABLE streams (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 240),
    deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
    config TEXT NOT NULL,
    config_revision INTEGER NOT NULL DEFAULT 0 CHECK(config_revision >= 0),
    metadata TEXT NOT NULL DEFAULT '{}' CHECK(length(CAST(metadata AS BLOB)) <= 65536),
    metadata_revision INTEGER NOT NULL DEFAULT 0 CHECK(metadata_revision >= 0),
    head INTEGER NOT NULL DEFAULT 0 CHECK(head >= 0),
    tail INTEGER NOT NULL DEFAULT 0 CHECK(tail >= head)
) STRICT;

CREATE UNIQUE INDEX streams_live_name ON streams(name) WHERE deleted=0;

CREATE TABLE segments (
    stream_id TEXT NOT NULL REFERENCES streams(id),
    start INTEGER NOT NULL CHECK(start >= 0),
    end INTEGER NOT NULL CHECK(end > start),
    record_count INTEGER NOT NULL CHECK(record_count = end-start),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
    min_accepted_at_ms INTEGER NOT NULL CHECK(min_accepted_at_ms >= 0),
    max_accepted_at_ms INTEGER NOT NULL CHECK(max_accepted_at_ms >= min_accepted_at_ms),
    sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
    PRIMARY KEY(stream_id,start)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX segments_active ON segments(stream_id) WHERE sealed=0;

CREATE TABLE records (
    stream_id TEXT NOT NULL REFERENCES streams(id),
    position INTEGER NOT NULL CHECK(position >= 0),
    payload BLOB NOT NULL CHECK(length(payload) <= 1048576),
    content_type TEXT NOT NULL CHECK(length(content_type) BETWEEN 1 AND 255),
    accepted_at_ms INTEGER NOT NULL CHECK(accepted_at_ms >= 0),
    PRIMARY KEY (stream_id, position)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER records_immutable BEFORE UPDATE ON records
BEGIN SELECT RAISE(ABORT, 'records are immutable'); END;

CREATE TABLE instance (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    id TEXT NOT NULL,
    origin TEXT NOT NULL,
    issuer_key BLOB NOT NULL
) STRICT;
CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    ssh_key TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    can_mint INTEGER NOT NULL CHECK(can_mint IN (0,1)),
    grants TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0)
) STRICT;
CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id),
    ceiling TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('ssh_session','api','api_url')),
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
CREATE TABLE challenges (
    id TEXT PRIMARY KEY,
    ssh_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5)
) STRICT;

CREATE TABLE auth_policy (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0),
    max_api_lifetime_seconds INTEGER NOT NULL CHECK(max_api_lifetime_seconds BETWEEN 1 AND 86400),
    max_url_lifetime_seconds INTEGER NOT NULL DEFAULT 31536000 CHECK(max_url_lifetime_seconds BETWEEN 1 AND 315360000)
) STRICT;
INSERT INTO auth_policy(singleton,max_api_lifetime_seconds) VALUES (1,86400);
CREATE TABLE auth_audit (
    sequence INTEGER PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    accepted_at INTEGER NOT NULL
) STRICT;

CREATE TABLE receipts (
    stream_id TEXT NOT NULL REFERENCES streams(id),
    principal_id TEXT NOT NULL, -- Principal ID or explicit hook grant ID.
    endpoint TEXT NOT NULL,
    key TEXT NOT NULL,
    digest BLOB NOT NULL,
    receipt TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(stream_id,principal_id,endpoint,key)
) STRICT, WITHOUT ROWID;
CREATE INDEX receipts_expiry ON receipts(expires_at);

CREATE TABLE creation_rules (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0),
    value TEXT NOT NULL
) STRICT;
INSERT INTO creation_rules(singleton,value) VALUES (1,'{"default":{"allow_append":false,"config":{"retention":{"mode":"infinite"},"max_record_bytes":"1048576","filters":[],"validators":[]}},"rules":[]}');

CREATE TABLE kv_attachments (
    stream_id TEXT PRIMARY KEY NOT NULL REFERENCES streams(id),
    id TEXT UNIQUE NOT NULL,
    applied_position INTEGER NOT NULL DEFAULT 0 CHECK(applied_position>=0)
) STRICT;
CREATE TABLE kv_items (
    attachment_id TEXT NOT NULL REFERENCES kv_attachments(id),
    key TEXT NOT NULL CHECK(length(CAST(key AS BLOB)) BETWEEN 1 AND 1024),
    value BLOB,
    content_type TEXT,
    revision INTEGER NOT NULL CHECK(revision>=0),
    CHECK((value IS NULL AND content_type IS NULL) OR (value IS NOT NULL AND content_type IS NOT NULL)),
    PRIMARY KEY(attachment_id,key)
) STRICT, WITHOUT ROWID;

CREATE TABLE hooks (
    id TEXT PRIMARY KEY NOT NULL,
    stream_id TEXT NOT NULL REFERENCES streams(id),
    owner_id TEXT NOT NULL REFERENCES principals(id),
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0),
    config TEXT NOT NULL,
    secret TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
    accepted INTEGER NOT NULL DEFAULT 0 CHECK(accepted>=0),
    dropped INTEGER NOT NULL DEFAULT 0 CHECK(dropped>=0),
    rejected INTEGER NOT NULL DEFAULT 0 CHECK(rejected>=0),
    errors INTEGER NOT NULL DEFAULT 0 CHECK(errors>=0)
) STRICT;
