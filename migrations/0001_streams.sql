CREATE TABLE streams (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 240),
    head INTEGER NOT NULL DEFAULT 0 CHECK(head >= 0),
    tail INTEGER NOT NULL DEFAULT 0 CHECK(tail >= head)
) STRICT;

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
