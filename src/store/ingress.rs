use super::{Store, identity::now};
use crate::{
    Error, Result,
    auth::Action,
    model::{Retention, StreamId},
    pipeline,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppendReceipt {
    pub outcome: String,
    pub stream_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_position: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deduplicated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_expires_at: Option<String>,
}
pub fn timestamp(seconds: i64) -> Result<String> {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| Error::Exhausted)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| Error::Exhausted)
}
fn key_valid(key: &str) -> bool {
    (1..=128).contains(&key.len()) && key.bytes().all(|b| (32..=126).contains(&b))
}
fn digest(payload: &[u8], content_type: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"patchwork/append/v1\0");
    hash.update((content_type.len() as u64).to_be_bytes());
    hash.update(content_type.as_bytes());
    hash.update((payload.len() as u64).to_be_bytes());
    hash.update(payload);
    hash.finalize().to_vec()
}
impl Store {
    fn saved_receipt(
        &self,
        id: &StreamId,
        principal: &str,
        key: &str,
        digest: &[u8],
    ) -> Result<Option<AppendReceipt>> {
        let row:Option<(Vec<u8>,String)>=self.connection.query_row("SELECT digest,receipt FROM receipts WHERE stream_id=?1 AND principal_id=?2 AND endpoint='raw' AND key=?3 AND expires_at>?4",params![id.as_str(),principal,key,now()?],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((saved, receipt)) = row {
            if saved != digest {
                return Err(Error::Conflict);
            }
            let mut receipt: AppendReceipt =
                serde_json::from_str(&receipt).map_err(|_| Error::DatabaseFormat)?;
            receipt.deduplicated = Some(true);
            Ok(Some(receipt))
        } else {
            Ok(None)
        }
    }
    pub fn append_authorized(
        &mut self,
        bearer: &str,
        id: &StreamId,
        payload: &[u8],
        content_type: &str,
        key: Option<&str>,
    ) -> Result<AppendReceipt> {
        if key.is_some_and(|k| !key_valid(k)) {
            return Err(Error::Invalid("idempotency key"));
        }
        self.authenticate(bearer)?;
        let principal = self.principal_id(bearer)?;
        let stream = self.stream(id)?;
        let config = self.config(id)?;
        if config.value.retention == Retention::None {
            return Err(Error::StreamMode);
        }
        let digest = digest(payload, content_type);
        let saved = key
            .map(|k| self.saved_receipt(id, &principal, k, &digest))
            .transpose()
            .map(Option::flatten);
        let had_receipt = matches!(saved, Ok(Some(_)));
        let candidate = if had_receipt {
            Ok(None)
        } else {
            pipeline::evaluate(&config.value, payload, content_type)
        };
        self.authorized(bearer, Action::RecordAppend, Some(id), &stream.name, |s| {
            if let Some(key) = key
                && let Some(receipt) = s.saved_receipt(id, &principal, key, &digest)?
            {
                return Ok(receipt);
            }
            if had_receipt {
                return Err(Error::ConfigChanged);
            }
            if s.config(id)?.revision != config.revision {
                return Err(Error::ConfigChanged);
            }
            let candidate = candidate?;
            let position = if let Some(bytes) = candidate {
                Some(s.append(id, &bytes, content_type)?)
            } else {
                None
            };
            let expires = now()? + 86400;
            let receipt = AppendReceipt {
                outcome: if position.is_some() {
                    "appended"
                } else {
                    "dropped"
                }
                .into(),
                stream_id: id.as_str().into(),
                position: position.map(|p| p.to_string()),
                next_position: position
                    .map(|p| p.next().map(|p| p.to_string()))
                    .transpose()?,
                deduplicated: key.map(|_| false),
                idempotency_expires_at: key.map(|_| timestamp(expires)).transpose()?,
            };
            if let Some(key) = key {
                s.connection
                    .execute("DELETE FROM receipts WHERE expires_at<=?1", [now()?])?;
                s.connection.execute(
                    "INSERT INTO receipts VALUES (?1,?2,'raw',?3,?4,?5,?6)",
                    params![
                        id.as_str(),
                        principal,
                        key,
                        digest,
                        serde_json::to_string(&receipt).map_err(|_| Error::Invalid("receipt"))?,
                        expires
                    ],
                )?;
            }
            Ok(receipt)
        })
    }
}
