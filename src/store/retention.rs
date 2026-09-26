use super::{Store, WriteTransaction};
use crate::{
    Error, Result,
    model::{Position, Retention, StreamConfig, StreamId},
};
use rusqlite::{Connection, params};
impl Store {
    pub(super) fn trim_in_transaction(
        connection: &Connection,
        id: &StreamId,
        config: &StreamConfig,
        budget: usize,
    ) -> Result<Position> {
        let (head, tail): (i64, i64) = connection.query_row(
            "SELECT head,tail FROM streams WHERE id=?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        // KV recovery has no snapshot producer yet. Keep its complete source.
        if connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM kv_attachments WHERE stream_id=?1)",
            [id.as_str()],
            |r| r.get::<_, bool>(0),
        )? {
            return Position::new(head);
        }
        let Retention::Bounded {
            max_age_seconds,
            max_bytes,
        } = config.retention
        else {
            return Position::new(head);
        };
        let mut bytes: i64 = connection.query_row(
            "SELECT coalesce(sum(payload_bytes),0) FROM segments WHERE stream_id=?1",
            [id.as_str()],
            |r| r.get(0),
        )?;
        let time: i64 = connection.query_row(
            "SELECT CAST(unixepoch('subsec')*1000 AS INTEGER)",
            [],
            |r| r.get(0),
        )?;
        let mut cutoff = head;
        let mut age_prefix = true;
        {
            let mut stmt=connection.prepare("SELECT position,length(payload),accepted_at_ms FROM records WHERE stream_id=?1 ORDER BY position LIMIT ?2")?;
            let mut rows = stmt.query(params![id.as_str(), budget as i64])?;
            while let Some(row) = rows.next()? {
                let pos: i64 = row.get(0)?;
                let size: i64 = row.get(1)?;
                let accepted: i64 = row.get(2)?;
                let old = max_age_seconds
                    .is_some_and(|seconds| accepted <= time.saturating_sub(seconds * 1000));
                age_prefix &= old;
                if !age_prefix && !max_bytes.is_some_and(|max| bytes > max) {
                    break;
                }
                cutoff = pos.checked_add(1).ok_or(Error::Exhausted)?;
                bytes -= size;
            }
        }
        if cutoff > head {
            connection.execute(
                "DELETE FROM records WHERE stream_id=?1 AND position<?2",
                params![id.as_str(), cutoff],
            )?;
            connection.execute(
                "DELETE FROM segments WHERE stream_id=?1 AND end<=?2",
                params![id.as_str(), cutoff],
            )?;
            connection.execute("UPDATE segments SET start=?2,record_count=end-?2,payload_bytes=(SELECT coalesce(sum(length(payload)),0) FROM records WHERE stream_id=?1 AND position>=?2 AND position<segments.end),min_accepted_at_ms=(SELECT min(accepted_at_ms) FROM records WHERE stream_id=?1 AND position>=?2 AND position<segments.end),max_accepted_at_ms=(SELECT max(accepted_at_ms) FROM records WHERE stream_id=?1 AND position>=?2 AND position<segments.end) WHERE stream_id=?1 AND start<?2 AND end>?2",params![id.as_str(),cutoff])?;
            connection.execute(
                "UPDATE streams SET head=?2 WHERE id=?1",
                params![id.as_str(), cutoff],
            )?;
        }
        debug_assert!(cutoff <= tail);
        Position::new(cutoff)
    }
    /// Bounded maintenance for plain streams. Recovery attachments are not
    /// accepted by this schema, so no recovery coverage can be bypassed.
    pub fn trim_stream(&mut self, id: &StreamId) -> Result<Position> {
        let tx = WriteTransaction::begin(&mut self.connection)?;
        let encoded: String = tx.query_row(
            "SELECT config FROM streams WHERE id=?1 AND deleted=0",
            [id.as_str()],
            |r| r.get(0),
        )?;
        let config: StreamConfig =
            serde_json::from_str(&encoded).map_err(|_| Error::DatabaseFormat)?;
        let head = Self::trim_in_transaction(&tx, id, &config, 1000)?;
        tx.commit()?;
        Ok(head)
    }
    pub(crate) fn maintenance_page(&mut self, after: &str) -> Result<String> {
        let ids = self
            .connection
            .prepare("SELECT id FROM streams WHERE id>?1 AND deleted=0 ORDER BY id LIMIT 32")?
            .query_map([after], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in &ids {
            self.trim_stream(&id.parse()?)?;
        }
        self.connection.execute("DELETE FROM receipts WHERE (stream_id,principal_id,endpoint,key) IN (SELECT stream_id,principal_id,endpoint,key FROM receipts WHERE expires_at<=unixepoch() LIMIT 1000)",[])?;
        Ok(if ids.len() == 32 {
            ids.last().cloned().unwrap_or_default()
        } else {
            String::new()
        })
    }
}
