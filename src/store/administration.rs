use super::{
    Store,
    identity::{json, now},
};
use crate::{
    Error, Result,
    auth::{self, Action, Grant, ssh, token::VerifiedToken},
    model::Revision,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalInput {
    pub ssh_public_key: String,
    pub enabled: bool,
    pub can_mint: bool,
    pub grants: Vec<Grant>,
}
#[derive(Serialize)]
pub struct PrincipalDescriptor {
    pub id: String,
    pub revision: String,
    #[serde(flatten)]
    pub config: PrincipalInput,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthPolicy {
    pub max_api_lifetime_seconds: i64,
    #[serde(default = "default_url_lifetime")]
    pub max_url_lifetime_seconds: i64,
}
fn default_url_lifetime() -> i64 {
    31_536_000
}
impl Store {
    pub(crate) fn instance_command<T>(
        &mut self,
        bearer: &str,
        action: Action,
        command: impl FnOnce(&mut Self, &str) -> Result<T>,
    ) -> Result<T> {
        let identity = self.identity()?;
        let verified = VerifiedToken::parse(bearer, identity.root.public())?;
        verified.check(
            action.as_str(),
            "instance",
            &identity.instance,
            "",
            &identity.instance,
            SystemTime::now(),
        )?;
        self.atomic(|s|{
            let rights=s.rights(&verified)?;
            if !auth::permits_instance(&rights.current,&rights.ceiling,action,&identity.instance){return Err(Error::Forbidden);}
            verified.check(action.as_str(),"instance",&identity.instance,"",&identity.instance,SystemTime::now())?;
            let value=command(s,&verified.principal)?;
            if matches!(action,Action::AdminWrite|Action::CredentialRevoke){s.connection.execute("INSERT INTO auth_audit(actor,action,resource,accepted_at) VALUES (?1,?2,?3,?4)",params![verified.principal,action.as_str(),identity.instance,now()?])?;}
            Ok(value)
        })
    }
    pub fn whoami(&self, bearer: &str) -> Result<serde_json::Value> {
        let identity = self.identity()?;
        let token = VerifiedToken::parse(bearer, identity.root.public())?;
        let rights = self.rights(&token)?;
        if token.instance != identity.instance {
            return Err(Error::Unauthorized);
        }
        // Identity inspection exposes no grants or secret material.
        token.check(
            "credential.inspect",
            "instance",
            &identity.instance,
            "",
            &identity.instance,
            SystemTime::now(),
        )?;
        Ok(
            serde_json::json!({"principal_id":token.principal,"credential_id":token.credential,"instance_id":identity.instance,"kind":rights.kind}),
        )
    }
    fn principal_descriptor(&self, id: &str) -> Result<PrincipalDescriptor> {
        let (key, enabled, mint, grants, revision): (String, bool, bool, String, i64) = self
            .connection
            .query_row(
                "SELECT ssh_key,enabled,can_mint,grants,revision FROM principals WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        Ok(PrincipalDescriptor {
            id: id.into(),
            revision: revision.to_string(),
            config: PrincipalInput {
                ssh_public_key: key,
                enabled,
                can_mint: mint,
                grants: serde_json::from_str(&grants).map_err(|_| Error::DatabaseFormat)?,
            },
        })
    }
    pub fn principals(
        &mut self,
        bearer: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<PrincipalDescriptor>> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::Invalid("page limit"));
        }
        self.instance_command(bearer, Action::AdminRead, |s, _| {
            let ids = s
                .connection
                .prepare("SELECT id FROM principals WHERE id>?1 ORDER BY id LIMIT ?2")?
                .query_map(params![after, limit as i64], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ids.iter().map(|id| s.principal_descriptor(id)).collect()
        })
    }
    pub fn put_principal(
        &mut self,
        bearer: &str,
        id: Option<&str>,
        expected: Option<Revision>,
        input: &PrincipalInput,
    ) -> Result<PrincipalDescriptor> {
        auth::validate_grants(&input.grants)?;
        let key = ssh::public_key(&input.ssh_public_key)?
            .to_openssh()
            .map_err(|_| Error::Invalid("SSH key"))?;
        let grants = json(&input.grants)?;
        self.instance_command(bearer,Action::AdminWrite,|s,_|{
            let id=id.map(str::to_owned).unwrap_or_else(||uuid::Uuid::new_v4().to_string());
            let duplicate:bool=s.connection.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE ssh_key=?1 AND id!=?2)",params![key,id],|r|r.get(0))?;
            if duplicate{return Err(Error::Conflict);}
            if let Some(revision)=expected {
                let current=s.principal_descriptor(&id)?;
                if current.revision!=revision.to_string(){return Err(Error::RevisionMismatch);}
                s.connection.execute("UPDATE principals SET ssh_key=?2,enabled=?3,can_mint=?4,grants=?5,revision=?6 WHERE id=?1",params![id,key,input.enabled,input.can_mint,grants,revision.next()?.get()])?;
            }else{
                s.connection.execute("INSERT INTO principals(id,ssh_key,enabled,can_mint,grants) VALUES (?1,?2,?3,?4,?5)",params![id,key,input.enabled,input.can_mint,grants])?;
            }
            // Refuse accidental removal of the last enabled administrator.
            let instance=s.identity()?.instance;
            let rows=s.connection.prepare("SELECT grants FROM principals WHERE enabled=1")?.query_map([],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            if !rows.iter().any(|row|serde_json::from_str::<Vec<Grant>>(row).is_ok_and(|g|auth::permits_instance(&g,&g,Action::AdminWrite,&instance))){return Err(Error::Conflict);}
            s.principal_descriptor(&id)
        })
    }
    pub fn policy(&mut self, bearer: &str) -> Result<(Revision, AuthPolicy)> {
        self.instance_command(bearer, Action::AdminRead, |s, _| {
            let (revision, max, max_url): (i64, i64, i64) = s.connection.query_row(
                "SELECT revision,max_api_lifetime_seconds,max_url_lifetime_seconds FROM auth_policy",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            Ok((
                Revision::new(revision)?,
                AuthPolicy {
                    max_api_lifetime_seconds: max,
                    max_url_lifetime_seconds: max_url,
                },
            ))
        })
    }
    pub fn replace_policy(
        &mut self,
        bearer: &str,
        expected: Revision,
        policy: &AuthPolicy,
    ) -> Result<Revision> {
        if !(1..=86400).contains(&policy.max_api_lifetime_seconds)
            || !(1..=315_360_000).contains(&policy.max_url_lifetime_seconds)
        {
            return Err(Error::Invalid("credential lifetime"));
        }
        self.instance_command(bearer, Action::AdminWrite, |s, _| {
            let next = expected.next()?;
            if s.connection.execute(
                "UPDATE auth_policy SET revision=?1,max_api_lifetime_seconds=?2,max_url_lifetime_seconds=?3 WHERE revision=?4",
                params![next.get(), policy.max_api_lifetime_seconds, policy.max_url_lifetime_seconds, expected.get()],
            )? != 1
            {
                return Err(Error::RevisionMismatch);
            }
            Ok(next)
        })
    }
    pub fn credentials(
        &mut self,
        bearer: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::Invalid("page limit"));
        }
        self.instance_command(bearer,Action::CredentialList,|s,principal|{
            let mut stmt=s.connection.prepare("SELECT id,ceiling,kind,expires_at,revoked FROM credentials WHERE principal_id=?1 AND id>?2 ORDER BY id LIMIT ?3")?;
            let mut rows=stmt.query(params![principal,after,limit as i64])?;let mut result=Vec::new();
            while let Some(row)=rows.next()?{let ceiling:String=row.get(1)?;result.push(serde_json::json!({"id":row.get::<_,String>(0)?,"grants":serde_json::from_str::<serde_json::Value>(&ceiling).map_err(|_|Error::DatabaseFormat)?,"kind":row.get::<_,String>(2)?,"expires_at":super::ingress::timestamp(row.get::<_,i64>(3)?)?,"revoked":row.get::<_,bool>(4)?}));}
            Ok(result)
        })
    }
}

impl Store {
    /// Explicit filesystem-authorized recovery, never exposed over HTTP.
    /// Restores access for this key while preserving existing credentials.
    pub fn recover_administrator(&mut self, public_key: &str) -> Result<serde_json::Value> {
        let key = ssh::public_key(public_key)?
            .to_openssh()
            .map_err(|_| Error::Invalid("SSH key"))?;
        self.atomic(|s| {
            let identity = s.identity()?;
            let grants = vec![
                Grant { actions: Action::ALL.to_vec(), selector: auth::Selector::Prefix(String::new()) },
                Grant { actions: vec![Action::AdminRead, Action::AdminWrite, Action::CredentialMint, Action::CredentialList, Action::CredentialRevoke], selector: auth::Selector::Instance(identity.instance.clone()) },
            ];
            let existing: Option<(String, i64)> = s.connection.query_row("SELECT id,revision FROM principals WHERE ssh_key=?1", [&key], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            let principal = if let Some((id, revision)) = existing {
                let revision = Revision::new(revision)?.next()?;
                s.connection.execute("UPDATE principals SET enabled=1,can_mint=1,grants=?2,revision=?3 WHERE id=?1", params![id,json(&grants)?,revision.get()])?;
                id
            } else {
                let id = uuid::Uuid::new_v4().to_string();
                s.connection.execute("INSERT INTO principals(id,ssh_key,enabled,can_mint,grants) VALUES (?1,?2,1,1,?3)", params![id,key,json(&grants)?])?;
                id
            };
            s.connection.execute("INSERT INTO auth_audit(actor,action,resource,accepted_at) VALUES ('local-operator','admin.recover',?1,?2)", params![principal,now()?])?;
            Ok(serde_json::json!({"principal_id":principal,"instance_id":identity.instance,"action":"administrator_restored"}))
        })
    }
}
