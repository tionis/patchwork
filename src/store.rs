//! Synchronous, internal-only storage for stream lifecycle and infinite-retention records.
//! A mutable connection serializes calls; there is no HTTP write admission yet.
use std::{path::Path, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    Error, Result,
    model::{
        Metadata, Position, ReadPage, Record, Retention, Revision, Segment, Stream, StreamConfig,
        StreamId, StreamName, Versioned,
    },
};

pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const SEGMENT_TARGET_BYTES: i64 = 8 * 1024 * 1024;
pub const SEGMENT_TARGET_RECORDS: i64 = 10_000;
const APPLICATION_ID: i64 = 0x50574348;
const SCHEMA_VERSION: i64 = 1;

mod administration;
mod identity;
pub use administration::{AuthPolicy, PrincipalDescriptor, PrincipalInput};
#[cfg(test)]
mod tests;
mod transaction;
pub use identity::{Challenge, CredentialReceipt};
use transaction::WriteTransaction;

pub struct Store {
    connection: Connection,
}

impl Store {
    /// Opens only the new format file; never opens/migrates legacy patchwork.db.
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let mut connection = Connection::open(data_dir.join("patchwork-v1.sqlite3"))?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        // Check ownership BEFORE changing journal mode or applying migrations.
        Self::check_format(&connection)?;
        let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if mode != "wal" {
            return Err(Error::DatabaseFormat);
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        Self::check_format(&tx)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == 0 {
            tx.execute_batch(include_str!("../migrations/0001_streams.sql"))?;
            tx.pragma_update(None, "application_id", APPLICATION_ID)?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        tx.commit()?;
        let store = Self { connection };
        store.check_ready()?;
        Ok(store)
    }

    fn check_format(connection: &Connection) -> Result<()> {
        let app: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tables: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        if !((app == 0 && version == 0 && tables == 0)
            || (app == APPLICATION_ID && version == SCHEMA_VERSION))
        {
            return Err(Error::DatabaseFormat);
        }
        Ok(())
    }

    pub fn check_ready(&self) -> Result<()> {
        self.connection.prepare(
            "SELECT config,config_revision,metadata,metadata_revision,deleted FROM streams WHERE 0",
        )?;
        Ok(())
    }

    pub fn create_stream(&mut self, name: &StreamName) -> Result<Stream> {
        self.create_stream_with(name, &StreamConfig::default(), &Metadata::default())
    }

    pub fn create_stream_with(
        &mut self,
        name: &StreamName,
        config: &StreamConfig,
        metadata: &Metadata,
    ) -> Result<Stream> {
        config.validate()?;
        let encoded = serde_json::to_string(config).map_err(|_| Error::Invalid("stream config"))?;
        let id = StreamId::random();
        let tx = WriteTransaction::begin(&mut self.connection)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM streams WHERE name=?1 AND deleted=0)",
            [name.as_str()],
            |r| r.get(0),
        )?;
        if exists {
            return Err(Error::Conflict);
        }
        tx.execute(
            "INSERT INTO streams(id,name,config,metadata) VALUES (?1,?2,?3,?4)",
            params![id.as_str(), name.as_str(), encoded, metadata.as_str()],
        )?;
        tx.commit()?;
        Ok(Stream {
            id,
            name: name.clone(),
            head: Position::ZERO,
            tail: Position::ZERO,
            config_revision: Revision::ZERO,
            metadata_revision: Revision::ZERO,
        })
    }

    pub fn stream(&self, id: &StreamId) -> Result<Stream> {
        let (name, head, tail, config_revision, metadata_revision): (String, i64, i64, i64, i64) = self
            .connection
            .query_row(
                "SELECT name,head,tail,config_revision,metadata_revision FROM streams WHERE id=?1 AND deleted=0",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        Ok(Stream {
            id: id.clone(),
            name: name.parse()?,
            head: Position::new(head)?,
            tail: Position::new(tail)?,
            config_revision: Revision::new(config_revision)?,
            metadata_revision: Revision::new(metadata_revision)?,
        })
    }

    /// Exact live-name lookup. Reading never creates a stream.
    pub fn lookup_stream(&self, name: &StreamName) -> Result<Stream> {
        let id: String = self
            .connection
            .query_row(
                "SELECT id FROM streams WHERE name=?1 AND deleted=0",
                [name.as_str()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        self.stream(&id.parse()?)
    }

    pub fn config(&self, id: &StreamId) -> Result<Versioned<StreamConfig>> {
        let (revision, value): (i64, String) = self
            .connection
            .query_row(
                "SELECT config_revision,config FROM streams WHERE id=?1 AND deleted=0",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        Ok(Versioned {
            revision: Revision::new(revision)?,
            value: serde_json::from_str(&value).map_err(|_| Error::DatabaseFormat)?,
        })
    }

    pub fn metadata(&self, id: &StreamId) -> Result<Versioned<Metadata>> {
        let (revision, value): (i64, String) = self
            .connection
            .query_row(
                "SELECT metadata_revision,metadata FROM streams WHERE id=?1 AND deleted=0",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        Ok(Versioned {
            revision: Revision::new(revision)?,
            value: value.parse()?,
        })
    }

    pub fn replace_config(
        &mut self,
        id: &StreamId,
        expected: Revision,
        config: &StreamConfig,
    ) -> Result<Revision> {
        config.validate()?;
        let encoded = serde_json::to_string(config).map_err(|_| Error::Invalid("stream config"))?;
        let tx = WriteTransaction::begin(&mut self.connection)?;
        let (revision, previous): (i64, String) = tx
            .query_row(
                "SELECT config_revision,config FROM streams WHERE id=?1 AND deleted=0",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        if revision != expected.get() {
            return Err(Error::RevisionMismatch);
        }
        let previous: StreamConfig =
            serde_json::from_str(&previous).map_err(|_| Error::DatabaseFormat)?;
        if previous.retention != config.retention {
            return Err(Error::StreamMode);
        }
        let next = expected.next()?;
        tx.execute(
            "UPDATE streams SET config=?2,config_revision=?3 WHERE id=?1",
            params![id.as_str(), encoded, next.get()],
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn replace_metadata(
        &mut self,
        id: &StreamId,
        expected: Revision,
        metadata: &Metadata,
    ) -> Result<Revision> {
        let tx = WriteTransaction::begin(&mut self.connection)?;
        let revision: i64 = tx
            .query_row(
                "SELECT metadata_revision FROM streams WHERE id=?1 AND deleted=0",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        if revision != expected.get() {
            return Err(Error::RevisionMismatch);
        }
        let next = expected.next()?;
        tx.execute(
            "UPDATE streams SET metadata=?2,metadata_revision=?3 WHERE id=?1",
            params![id.as_str(), metadata.as_str(), next.get()],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// Logical deletion releases the name. Reclamation is separate; the old ID
    /// remains a tombstone and cannot be used to access a recreated resource.
    pub fn delete_stream(&mut self, id: &StreamId, expected_config: Revision) -> Result<()> {
        let tx = WriteTransaction::begin(&mut self.connection)?;
        let revision: i64 = tx
            .query_row(
                "SELECT config_revision FROM streams WHERE id=?1 AND deleted=0",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        if revision != expected_config.get() {
            return Err(Error::RevisionMismatch);
        }
        let next = expected_config.next()?;
        tx.execute(
            "UPDATE streams SET deleted=1,config_revision=?2 WHERE id=?1",
            params![id.as_str(), next.get()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Bounded internal summary page, ordered by segment start (inclusive).
    pub fn segments(
        &mut self,
        id: &StreamId,
        from: Position,
        limit: usize,
    ) -> Result<Vec<Segment>> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::Invalid("segment page limit"));
        }
        let tx = self.connection.savepoint()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM streams WHERE id=?1 AND deleted=0)",
            [id.as_str()],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::NotFound);
        }
        let mut statement = tx.prepare("SELECT start,end,record_count,payload_bytes,min_accepted_at_ms,max_accepted_at_ms,sealed
            FROM segments WHERE stream_id=?1 AND start>=?2 ORDER BY start LIMIT ?3")?;
        let mut rows = statement.query(params![id.as_str(), from.get(), limit as i64])?;
        let mut segments = Vec::new();
        while let Some(row) = rows.next()? {
            segments.push(Segment {
                start: Position::new(row.get(0)?)?,
                end: Position::new(row.get(1)?)?,
                record_count: row.get(2)?,
                payload_bytes: row.get(3)?,
                min_accepted_at_ms: row.get(4)?,
                max_accepted_at_ms: row.get(5)?,
                sealed: row.get(6)?,
            });
        }
        Ok(segments)
    }

    pub fn append(
        &mut self,
        id: &StreamId,
        payload: &[u8],
        content_type: &str,
    ) -> Result<Position> {
        if payload.len() > MAX_RECORD_BYTES {
            return Err(Error::TooLarge);
        }
        if content_type.is_empty()
            || content_type.len() > 255
            || !content_type.bytes().all(|c| (32..=126).contains(&c))
        {
            return Err(Error::Invalid("content type"));
        }
        let tx = WriteTransaction::begin(&mut self.connection)?;
        let (tail, encoded): (i64, String) = tx
            .query_row(
                "SELECT tail,config FROM streams WHERE id=?1 AND deleted=0",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let config: StreamConfig =
            serde_json::from_str(&encoded).map_err(|_| Error::DatabaseFormat)?;
        if config.retention == Retention::None {
            return Err(Error::StreamMode);
        }
        if payload.len() > config.max_record_bytes {
            return Err(Error::TooLarge);
        }
        let position = Position::new(tail)?;
        let next = position.next()?;
        let accepted_at_ms: i64 = tx.query_row(
            "SELECT CAST(unixepoch('subsec')*1000 AS INTEGER)",
            [],
            |r| r.get(0),
        )?;
        tx.execute("INSERT INTO records(stream_id,position,payload,content_type,accepted_at_ms) VALUES (?1,?2,?3,?4,?5)",
            params![id.as_str(), position.get(), payload, content_type, accepted_at_ms])?;
        let updated = tx.execute(
            "UPDATE segments SET end=?2,record_count=record_count+1,payload_bytes=payload_bytes+?3,
             min_accepted_at_ms=min(min_accepted_at_ms,?4),max_accepted_at_ms=max(max_accepted_at_ms,?4),
             sealed=(record_count+1>=?5 OR payload_bytes+?3>=?6)
             WHERE stream_id=?1 AND sealed=0 AND end=?7",
            params![id.as_str(), next.get(), payload.len() as i64, accepted_at_ms,
                SEGMENT_TARGET_RECORDS, SEGMENT_TARGET_BYTES, position.get()],
        )?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO segments VALUES (?1,?2,?3,1,?4,?5,?5,0)",
                params![
                    id.as_str(),
                    position.get(),
                    next.get(),
                    payload.len() as i64,
                    accepted_at_ms
                ],
            )?;
        }
        tx.execute(
            "UPDATE streams SET tail=?2 WHERE id=?1",
            params![id.as_str(), next.get()],
        )?;
        tx.commit()?;
        Ok(position)
    }

    /// Bounded snapshot read; a record exceeding the byte budget is returned alone.
    pub fn read(
        &mut self,
        id: &StreamId,
        from: Position,
        limit: usize,
        max_bytes: usize,
    ) -> Result<ReadPage> {
        if !(1..=1000).contains(&limit) || !(1..=16 * 1024 * 1024).contains(&max_bytes) {
            return Err(Error::Invalid("read budget"));
        }
        let tx = self.connection.savepoint()?;
        let (head, tail, encoded): (i64, i64, String) = tx
            .query_row(
                "SELECT head,tail,config FROM streams WHERE id=?1 AND deleted=0",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let config: StreamConfig =
            serde_json::from_str(&encoded).map_err(|_| Error::DatabaseFormat)?;
        if config.retention == Retention::None {
            return Err(Error::StreamMode);
        }
        let (head, tail) = (Position::new(head)?, Position::new(tail)?);
        if from < head {
            return Err(Error::HistoryLost);
        }
        if from > tail {
            return Err(Error::PositionAhead);
        }
        let mut statement = tx.prepare("SELECT position,payload,content_type,accepted_at_ms FROM records WHERE stream_id=?1 AND position>=?2 ORDER BY position LIMIT ?3")?;
        let mut rows = statement.query(params![id.as_str(), from.get(), limit as i64])?;
        let mut records = Vec::new();
        let mut bytes = 0;
        let mut next_position = from;
        while let Some(row) = rows.next()? {
            let payload: Vec<u8> = row.get(1)?;
            if !records.is_empty() && bytes + payload.len() > max_bytes {
                break;
            }
            let position = Position::new(row.get(0)?)?;
            if position != next_position {
                return Err(Error::DatabaseFormat);
            }
            next_position = position.next()?;
            bytes += payload.len();
            records.push(Record {
                position,
                payload,
                content_type: row.get(2)?,
                accepted_at_ms: row.get(3)?,
            });
        }
        Ok(ReadPage {
            head,
            tail,
            next_position,
            records,
        })
    }
}
