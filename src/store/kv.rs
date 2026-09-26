//! Authoritative KV state and the final, unbypassable append validator.
use super::{Store, identity::now, ingress};
use crate::{
    Error, Result,
    auth::Action,
    model::{Position, Revision, StreamId},
    pipeline,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
pub const MAX_VALUE_BYTES: usize = 720 * 1024;
pub const TYPE: &str = "patchwork/kv/v1";
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Absent,
    Revision { revision: String },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Put,
    Delete,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub version: u8,
    pub op: Operation,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
}
pub fn validate_key(key: &str) -> Result<()> {
    if !(1..=1024).contains(&key.len()) {
        return Err(Error::Invalid("KV key"));
    }
    Ok(())
}
impl Event {
    pub fn put(
        key: String,
        bytes: &[u8],
        content_type: String,
        condition: Option<Condition>,
    ) -> Result<Self> {
        if bytes.len() > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
        let event = Self {
            version: 1,
            op: Operation::Put,
            key,
            value_base64: Some(STANDARD.encode(bytes)),
            content_type: Some(content_type),
            condition,
        };
        event.validate()?;
        Ok(event)
    }
    pub fn delete(key: String, condition: Option<Condition>) -> Result<Self> {
        let event = Self {
            version: 1,
            op: Operation::Delete,
            key,
            value_base64: None,
            content_type: None,
            condition,
        };
        event.validate()?;
        Ok(event)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| Error::Invalid("KV event"))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > super::MAX_RECORD_BYTES {
            return Err(Error::TooLarge);
        }
        let event: Self = serde_json::from_slice(bytes).map_err(|_| Error::Rejected)?;
        event.validate()?;
        Ok(event)
    }
    fn validate(&self) -> Result<()> {
        validate_key(&self.key)?;
        if self.version != 1 {
            return Err(Error::Rejected);
        }
        if let Some(Condition::Revision { revision }) = &self.condition {
            revision.parse::<Position>()?;
        }
        match self.op {
            Operation::Put => {
                let encoded = self.value_base64.as_ref().ok_or(Error::Rejected)?;
                if encoded.len() > MAX_VALUE_BYTES.div_ceil(3) * 4 {
                    return Err(Error::TooLarge);
                }
                let value = STANDARD.decode(encoded).map_err(|_| Error::Rejected)?;
                if value.len() > MAX_VALUE_BYTES {
                    return Err(Error::TooLarge);
                }
                if STANDARD.encode(&value) != *encoded {
                    return Err(Error::Rejected);
                }
                pipeline::validate_content_type(
                    self.content_type.as_deref().ok_or(Error::Rejected)?,
                )?;
            }
            Operation::Delete => {
                if self.value_base64.is_some()
                    || self.content_type.is_some()
                    || self.condition == Some(Condition::Absent)
                {
                    return Err(Error::Rejected);
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Attachment {
    pub id: String,
    pub stream_id: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub applied_position: String,
    pub config_revision: String,
}
#[derive(Debug)]
pub struct Value {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub revision: String,
    pub applied_position: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<String>,
    pub applied_position: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deduplicated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_expires_at: Option<String>,
}
#[derive(Serialize)]
pub struct Entry {
    pub key: String,
    pub revision: String,
}
#[derive(Serialize)]
pub struct Page {
    pub items: Vec<Entry>,
    pub next_cursor: Option<String>,
    pub applied_position: String,
}
fn attachment(connection: &Connection, id: &StreamId, aid: Option<&str>) -> Result<(String, i64)> {
    let row: (String, i64) = connection
        .query_row(
            "SELECT id,applied_position FROM kv_attachments WHERE stream_id=?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    if aid.is_some_and(|aid| aid != row.0) {
        return Err(Error::NotFound);
    }
    Ok(row)
}
fn current(connection: &Connection, aid: &str, key: &str) -> Result<Option<i64>> {
    Ok(connection
        .query_row(
            "SELECT revision FROM kv_items WHERE attachment_id=?1 AND key=?2 AND value IS NOT NULL",
            params![aid, key],
            |r| r.get(0),
        )
        .optional()?)
}
fn condition(event: &Event, revision: Option<i64>) -> Result<()> {
    let matches = match &event.condition {
        None => true,
        Some(Condition::Absent) => revision.is_none(),
        Some(Condition::Revision { revision: expected }) => {
            revision == Some(expected.parse::<Position>()?.get())
        }
    };
    if !matches {
        return Err(Error::RevisionMismatch);
    }
    Ok(())
}
impl Store {
    pub fn enable_kv(
        &mut self,
        bearer: &str,
        id: &StreamId,
        expected: Revision,
    ) -> Result<Attachment> {
        self.authenticate(bearer)?;
        let stream = self.stream(id)?;
        self.authorized(
            bearer,
            Action::AttachmentWrite,
            Some(id),
            &stream.name,
            |s| {
                let stream = s.stream(id)?;
                if stream.config_revision != expected {
                    return Err(Error::RevisionMismatch);
                }
                if !stream.retained || stream.tail != Position::ZERO {
                    return Err(Error::Conflict);
                }
                let exists: bool = s.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM kv_attachments WHERE stream_id=?1)",
                    [id.as_str()],
                    |r| r.get(0),
                )?;
                if exists {
                    return Err(Error::Conflict);
                }
                let aid = format!("att_{}", uuid::Uuid::new_v4());
                let revision = expected.next()?;
                s.connection.execute(
                    "INSERT INTO kv_attachments(stream_id,id) VALUES (?1,?2)",
                    params![id.as_str(), aid],
                )?;
                s.connection.execute(
                    "UPDATE streams SET config_revision=?2 WHERE id=?1",
                    params![id.as_str(), revision.get()],
                )?;
                Ok(Attachment {
                    id: aid,
                    stream_id: id.as_str().into(),
                    kind: TYPE,
                    applied_position: "0".into(),
                    config_revision: revision.to_string(),
                })
            },
        )
    }
    pub fn kv_attachments(&mut self, bearer: &str, id: &StreamId) -> Result<Vec<Attachment>> {
        self.authenticate(bearer)?;
        let stream = self.stream(id)?;
        self.authorized(
            bearer,
            Action::AttachmentRead,
            Some(id),
            &stream.name,
            |s| {
                let revision = s.stream(id)?.config_revision;
                match attachment(&s.connection, id, None) {
                    Ok((aid, applied)) => Ok(vec![Attachment {
                        id: aid,
                        stream_id: id.as_str().into(),
                        kind: TYPE,
                        applied_position: applied.to_string(),
                        config_revision: revision.to_string(),
                    }]),
                    Err(Error::NotFound) => Ok(vec![]),
                    Err(e) => Err(e),
                }
            },
        )
    }
    pub(super) fn apply_kv_event(
        connection: &Connection,
        id: &StreamId,
        bytes: &[u8],
        position: Position,
    ) -> Result<()> {
        let (aid, applied) = match attachment(connection, id, None) {
            Ok(v) => v,
            Err(Error::NotFound) => return Ok(()),
            Err(e) => return Err(e),
        };
        if applied != position.get() {
            return Err(Error::Conflict);
        }
        let event = Event::parse(bytes)?;
        condition(&event, current(connection, &aid, &event.key)?)?;
        let value = event
            .value_base64
            .map(|v| STANDARD.decode(v).map_err(|_| Error::Rejected))
            .transpose()?;
        connection.execute("INSERT INTO kv_items(attachment_id,key,value,content_type,revision) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(attachment_id,key) DO UPDATE SET value=excluded.value,content_type=excluded.content_type,revision=excluded.revision",params![aid,event.key,value,event.content_type,position.get()])?;
        connection.execute(
            "UPDATE kv_attachments SET applied_position=?2 WHERE id=?1",
            params![aid, position.next()?.get()],
        )?;
        Ok(())
    }
    pub fn kv_get(&mut self, bearer: &str, id: &StreamId, aid: &str, key: &str) -> Result<Value> {
        validate_key(key)?;
        self.authenticate(bearer)?;
        let st = self.stream(id)?;
        self.authorized(bearer,Action::KvRead,Some(id),&st.name,|s|{
            let (_,applied)=attachment(&s.connection,id,Some(aid))?;
            let (bytes,content_type,revision):(Vec<u8>,String,i64)=s.connection.query_row("SELECT value,content_type,revision FROM kv_items WHERE attachment_id=?1 AND key=?2 AND value IS NOT NULL",params![aid,key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(Error::NotFound)?;
            Ok(Value{bytes,content_type,revision:revision.to_string(),applied_position:applied.to_string()})
        })
    }
    #[allow(clippy::too_many_arguments)] // Explicit stream/attachment and bounded page selectors.
    pub fn kv_list(
        &mut self,
        bearer: &str,
        id: &StreamId,
        aid: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page> {
        if prefix.len() > 1024
            || after.is_some_and(|v| v.len() > 1024)
            || !(1..=1000).contains(&limit)
        {
            return Err(Error::Invalid("KV page"));
        }
        self.authenticate(bearer)?;
        let st = self.stream(id)?;
        self.authorized(bearer,Action::KvRead,Some(id),&st.name,|s|{
            let (_,applied)=attachment(&s.connection,id,Some(aid))?;
            let mut stmt=s.connection.prepare("SELECT key,revision FROM kv_items WHERE attachment_id=?1 AND key>=?2 AND (?3 IS NULL OR key>?3) AND value IS NOT NULL ORDER BY key LIMIT ?4")?;
            let mut rows=stmt.query(params![aid,prefix,after,(limit+1)as i64])?;let mut items=Vec::new();
            while let Some(row)=rows.next()? {let key:String=row.get(0)?;if !key.starts_with(prefix){break;}items.push(Entry{key,revision:row.get::<_,i64>(1)?.to_string()});}
            let next=if items.len()>limit {items.pop();items.last().map(|e|e.key.clone())}else{None};
            Ok(Page{items,next_cursor:next,applied_position:applied.to_string()})
        })
    }
    pub fn kv_mutate(
        &mut self,
        bearer: &str,
        id: &StreamId,
        aid: &str,
        event: &Event,
        key: Option<&str>,
    ) -> Result<Receipt> {
        if key.is_some_and(|k| !ingress::key_valid(k)) {
            return Err(Error::Invalid("idempotency key"));
        }
        let original = event.encode()?;
        self.authenticate(bearer)?;
        let principal = self.principal_id(bearer)?;
        let st = self.stream(id)?;
        let config = self.config(id)?;
        let endpoint = format!(
            "kv:{aid}:{}",
            if event.op == Operation::Put {
                "put"
            } else {
                "delete"
            }
        );
        let hash = ingress::digest(&original, "application/json");
        let cached = key
            .map(|key| self.load_receipt::<Receipt>((id, &principal, &endpoint, key), &hash))
            .transpose()
            .map(Option::flatten);
        let had_receipt = matches!(cached, Ok(Some(_)));
        let prepared = if had_receipt {
            Ok(None)
        } else {
            pipeline::evaluate(&config.value, &original, "application/json")
        };
        self.authorized(bearer, Action::KvWrite, Some(id), &st.name, |s| {
            let (_, applied) = attachment(&s.connection, id, Some(aid))?;
            if let Some(key) = key
                && let Some(mut receipt) =
                    s.load_receipt::<Receipt>((id, &principal, &endpoint, key), &hash)?
            {
                receipt.deduplicated = Some(true);
                return Ok(receipt);
            }
            if had_receipt || s.config(id)?.revision != config.revision {
                return Err(Error::ConfigChanged);
            }
            let before = current(&s.connection, aid, &event.key)?;
            condition(event, before)?;
            let position = if event.op == Operation::Delete && before.is_none() {
                None
            } else {
                let candidate = prepared?.ok_or(Error::Rejected)?;
                // Formatting may change; no value/semantic transforms are approved.
                if Event::parse(&candidate)? != *event {
                    return Err(Error::Rejected);
                }
                Some(s.append(id, &candidate, "application/json")?)
            };
            let expires = now()? + 86400;
            let receipt = Receipt {
                status: if event.op == Operation::Delete {
                    204
                } else if before.is_none() {
                    201
                } else {
                    200
                },
                revision: position.map(|p| p.to_string()),
                position: position.map(|p| p.to_string()),
                applied_position: position
                    .map(|p| p.next().map(|p| p.to_string()))
                    .transpose()?
                    .unwrap_or_else(|| applied.to_string()),
                deduplicated: key.map(|_| false),
                idempotency_expires_at: key.map(|_| ingress::timestamp(expires)).transpose()?,
            };
            if let Some(key) = key {
                s.save_receipt((id, &principal, &endpoint, key), &hash, &receipt, expires)?;
            }
            Ok(receipt)
        })
    }
}
