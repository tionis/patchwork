//! GitHub HMAC-SHA256 ingress, scoped to an explicitly administered target.
use super::{AppendReceipt, Store, identity::now, ingress};
use crate::{
    Error, Result,
    auth::{self, Action, Grant, Selector, token::VerifiedToken},
    model::{Retention, Revision, StreamId},
    pipeline,
};
use hmac::{Hmac, Mac};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    Raw,
    Wakeup,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub stream_id: String,
    pub enabled: bool,
    /// Exact Git ref; None accepts all push refs.
    pub git_ref: Option<String>,
    pub transform: Transform,
    pub success_status: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub config: Config,
    pub secret: Option<String>,
}
#[derive(Serialize)]
pub struct Descriptor {
    pub id: String,
    pub revision: String,
    pub config: Config,
    pub counters: Value,
}
struct Stored {
    id: String,
    owner: String,
    revision: i64,
    config: Config,
    secret: String,
}
pub struct Delivery {
    pub stream_id: String,
    pub name: String,
    pub status: u16,
    pub receipt: AppendReceipt,
    pub live: Option<Vec<u8>>,
}
pub fn verify_signature(secret: &[u8], body: &[u8], signature: &str) -> Result<()> {
    let hex = signature
        .strip_prefix("sha256=")
        .filter(|s| s.len() == 64)
        .ok_or(Error::Unauthorized)?;
    let mut tag = [0u8; 32];
    for (out, pair) in tag.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair).map_err(|_| Error::Unauthorized)?;
        *out = u8::from_str_radix(pair, 16).map_err(|_| Error::Unauthorized)?;
    }
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).map_err(|_| Error::Unauthorized)?;
    mac.update(body);
    mac.verify_slice(&tag).map_err(|_| Error::Unauthorized)
}
fn transform(config: &Config, event: &str, body: &[u8]) -> Result<Option<Vec<u8>>> {
    let value: Value = serde_json::from_slice(body).map_err(|_| Error::Rejected)?;
    if !value.is_object() {
        return Err(Error::Rejected);
    }
    if event != "push" {
        return Ok(None);
    }
    let git_ref = value
        .get("ref")
        .and_then(Value::as_str)
        .filter(|s| s.len() <= 1024)
        .ok_or(Error::Rejected)?;
    if config.git_ref.as_ref().is_some_and(|r| r != git_ref) {
        return Ok(None);
    }
    match config.transform {
        Transform::Raw => Ok(Some(body.to_vec())),
        Transform::Wakeup => {
            let repository = value
                .pointer("/repository/full_name")
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 512)
                .ok_or(Error::Rejected)?;
            let after = value
                .get("after")
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 128)
                .ok_or(Error::Rejected)?;
            Ok(Some(serde_json::to_vec(&json!({"provider":"github","repository":repository,"ref":git_ref,"after":after})).map_err(|_|Error::Rejected)?))
        }
    }
}
impl Store {
    fn load_hook(&self, id: &str) -> Result<Stored> {
        let (owner, revision, config, secret): (String, i64, String, String) = self
            .connection
            .query_row(
                "SELECT owner_id,revision,config,secret FROM hooks WHERE id=?1 AND deleted=0",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        Ok(Stored {
            id: id.into(),
            owner,
            revision,
            config: serde_json::from_str(&config).map_err(|_| Error::DatabaseFormat)?,
            secret,
        })
    }
    fn hook_descriptor(&self, row: Stored) -> Result<Descriptor> {
        let counts: (i64, i64, i64, i64) = self.connection.query_row(
            "SELECT accepted,dropped,rejected,errors FROM hooks WHERE id=?1",
            [&row.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        Ok(Descriptor {
            id: row.id,
            revision: row.revision.to_string(),
            config: row.config,
            counters: json!({"accepted":counts.0.to_string(),"dropped":counts.1.to_string(),"rejected":counts.2.to_string(),"errors":counts.3.to_string()}),
        })
    }
    fn unattenuated(&self, bearer: &str) -> Result<()> {
        let identity = self.identity()?;
        if !VerifiedToken::parse(bearer, identity.root.public())?.is_unattenuated() {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub fn put_hook(
        &mut self,
        bearer: &str,
        id: Option<&str>,
        expected: Option<Revision>,
        input: &Input,
    ) -> Result<Descriptor> {
        self.authenticate(bearer)?;
        self.unattenuated(bearer)?;
        let sid: StreamId = input.config.stream_id.parse()?;
        let st = self.stream(&sid)?;
        if !matches!(input.config.success_status, 200 | 204)
            || input
                .config
                .git_ref
                .as_ref()
                .is_some_and(|r| r.is_empty() || r.len() > 1024)
        {
            return Err(Error::Invalid("hook config"));
        }
        if input
            .secret
            .as_ref()
            .is_some_and(|s| !(16..=512).contains(&s.len()))
        {
            return Err(Error::Invalid("hook secret length"));
        }
        if id.is_none() && input.secret.is_none() {
            return Err(Error::Invalid("hook secret required"));
        }
        let principal = self.principal_id(bearer)?;
        self.authorized(bearer,Action::HookManage,Some(&sid),&st.name,|s|s.authorized(bearer,Action::RecordAppend,Some(&sid),&st.name,|s|{
            let hid=if let Some(id)=id{
                let old=s.load_hook(id)?;
                if old.config.stream_id!=sid.as_str(){return Err(Error::Conflict);}
                if expected.map(|r|r.get())!=Some(old.revision){return Err(Error::RevisionMismatch);}
                let revision=Revision::new(old.revision)?.next()?;
                let secret=input.secret.as_ref().unwrap_or(&old.secret);
                s.connection.execute("UPDATE hooks SET owner_id=?2,revision=?3,config=?4,secret=?5 WHERE id=?1",params![id,principal,revision.get(),serde_json::to_string(&input.config).map_err(|_|Error::Invalid("hook config"))?,secret])?;
                id.to_owned()
            }else{
                let id=format!("hook_{}",uuid::Uuid::new_v4());
                s.connection.execute("INSERT INTO hooks(id,stream_id,owner_id,config,secret) VALUES (?1,?2,?3,?4,?5)",params![id,sid.as_str(),principal,serde_json::to_string(&input.config).map_err(|_|Error::Invalid("hook config"))?,input.secret])?;
                id
            };
            s.connection.execute("INSERT INTO auth_audit(actor,action,resource,accepted_at) VALUES (?1,'hook.manage',?2,?3)",params![principal,hid,now()?])?;
            s.hook_descriptor(s.load_hook(&hid)?)
        }))
    }
    pub fn hook(&mut self, bearer: &str, id: &str) -> Result<Descriptor> {
        self.authenticate(bearer)?;
        let hook = self.load_hook(id)?;
        let sid = hook.config.stream_id.parse()?;
        let st = self.stream(&sid)?;
        self.authorized(bearer, Action::HookManage, Some(&sid), &st.name, |s| {
            s.hook_descriptor(s.load_hook(id)?)
        })
    }
    pub fn hooks(
        &mut self,
        bearer: &str,
        after: &str,
        limit: usize,
    ) -> Result<(Vec<Descriptor>, Option<String>)> {
        self.authenticate(bearer)?;
        if !(1..=100).contains(&limit) {
            return Err(Error::Invalid("hook page"));
        }
        let ids = self
            .connection
            .prepare("SELECT id FROM hooks WHERE deleted=0 AND id>?1 ORDER BY id LIMIT 1000")?
            .query_map([after], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut result = Vec::new();
        let mut next = None;
        for (index, id) in ids.iter().enumerate() {
            match self.hook(bearer, id) {
                Ok(value) => result.push(value),
                Err(Error::Forbidden | Error::NotFound) => {}
                Err(e) => return Err(e),
            }
            if result.len() == limit || index == 999 {
                next = Some(id.clone());
                break;
            }
        }
        Ok((result, next))
    }
    pub fn delete_hook(&mut self, bearer: &str, id: &str, expected: Revision) -> Result<()> {
        self.authenticate(bearer)?;
        let hook = self.load_hook(id)?;
        let sid = hook.config.stream_id.parse()?;
        let st = self.stream(&sid)?;
        self.authorized(bearer, Action::HookManage, Some(&sid), &st.name, |s| {
            if s.load_hook(id)?.revision != expected.get() {
                return Err(Error::RevisionMismatch);
            }
            s.connection.execute(
                "UPDATE hooks SET deleted=1,revision=?2 WHERE id=?1",
                params![id, expected.next()?.get()],
            )?;
            Ok(())
        })
    }
    fn hook_authority(&self, hook: &Stored) -> Result<crate::model::Stream> {
        if !hook.config.enabled {
            return Err(Error::Forbidden);
        }
        let grants: String = self
            .connection
            .query_row(
                "SELECT grants FROM principals WHERE id=?1 AND enabled=1",
                [&hook.owner],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::Forbidden)?;
        let grants: Vec<Grant> =
            serde_json::from_str(&grants).map_err(|_| Error::DatabaseFormat)?;
        let sid: StreamId = hook.config.stream_id.parse()?;
        let st = self.stream(&sid)?;
        // Fixed target is the immutable service-grant ceiling. Current owner
        // rights still apply; receipt possession never supplies authority.
        let ceiling = [Grant {
            actions: vec![Action::RecordAppend],
            selector: Selector::Stream(sid.as_str().into()),
        }];
        if !auth::permits(
            &grants,
            &ceiling,
            Action::RecordAppend,
            Some(&sid),
            &st.name,
        ) {
            return Err(Error::Forbidden);
        }
        Ok(st)
    }
    pub fn ingest_hook(
        &mut self,
        id: &str,
        event: &str,
        delivery: &str,
        signature: &str,
        body: &[u8],
    ) -> Result<Delivery> {
        let result = self.ingest_hook_inner(id, event, delivery, signature, body);
        if let Err(error) = &result {
            let column = if matches!(error, Error::Storage(_) | Error::Busy | Error::Exhausted) {
                "errors"
            } else {
                "rejected"
            };
            let _=self.connection.execute(&format!("UPDATE hooks SET {column}={column}+1 WHERE id=?1 AND {column}<9223372036854775807"),[id]);
        }
        result
    }
    fn ingest_hook_inner(
        &mut self,
        id: &str,
        event: &str,
        delivery: &str,
        signature: &str,
        body: &[u8],
    ) -> Result<Delivery> {
        if body.len() > super::MAX_RECORD_BYTES {
            return Err(Error::TooLarge);
        }
        let hook = self.load_hook(id)?;
        verify_signature(hook.secret.as_bytes(), body, signature)?;
        if event.is_empty()
            || event.len() > 64
            || !event
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::Invalid("provider event"));
        }
        uuid::Uuid::parse_str(delivery).map_err(|_| Error::Invalid("provider delivery ID"))?;
        let st = self.hook_authority(&hook)?;
        let config = self.config(&st.id)?;
        let retained = config.value.retention != Retention::None;
        let hash = ingress::digest(body, &format!("github:{event}:application/json"));
        let cached = if retained {
            self.load_receipt::<AppendReceipt>((&st.id, id, "hook", delivery), &hash)
        } else {
            Ok(None)
        };
        let had_receipt = matches!(cached, Ok(Some(_)));
        let prepared = if had_receipt {
            Ok(None)
        } else {
            transform(&hook.config, event, body).and_then(|v| {
                v.map(|bytes| pipeline::evaluate(&config.value, &bytes, "application/json"))
                    .transpose()
                    .map(Option::flatten)
            })
        };
        self.atomic(|s|{
            let current=s.load_hook(id)?;let st=s.hook_authority(&current)?;
            if current.revision!=hook.revision {return Err(Error::ConfigChanged);}
            if retained && let Some(mut receipt)=s.load_receipt::<AppendReceipt>((&st.id,id,"hook",delivery),&hash)? {
                receipt.deduplicated=Some(true);
                return Ok(Delivery{stream_id:st.id.as_str().into(),name:st.name.as_str().into(),status:current.config.success_status,receipt,live:None});
            }
            if had_receipt || s.config(&st.id)?.revision!=config.revision {return Err(Error::ConfigChanged);}
            let candidate=prepared?;let dropped=candidate.is_none();
            let position=if retained{candidate.as_ref().map(|v|s.append(&st.id,v,"application/json")).transpose()?}else{None};
            let expires=now()?+86400;
            let receipt=AppendReceipt{outcome:if dropped{"dropped"}else if retained{"appended"}else{"published"}.into(),stream_id:st.id.as_str().into(),position:position.map(|p|p.to_string()),next_position:position.map(|p|p.next().map(|p|p.to_string())).transpose()?,deduplicated:retained.then_some(false),idempotency_expires_at:if retained{Some(ingress::timestamp(expires)?)}else{None}};
            if retained{s.save_receipt((&st.id,id,"hook",delivery),&hash,&receipt,expires)?;}
            let column=if dropped{"dropped"}else{"accepted"};
            if s.connection.execute(&format!("UPDATE hooks SET {column}={column}+1 WHERE id=?1 AND {column}<9223372036854775807"),[id])?!=1{return Err(Error::Exhausted);}
            Ok(Delivery{stream_id:st.id.as_str().into(),name:st.name.as_str().into(),status:current.config.success_status,receipt,live:if retained{None}else{candidate}})
        })
    }
}
