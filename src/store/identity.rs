use super::Store;
use crate::{
    Error, Result,
    auth::{
        self, Action, Grant, Selector, ssh,
        token::{self, VerifiedToken},
    },
    model::{StreamId, StreamName},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use biscuit_auth::{Algorithm, KeyPair, PrivateKey};
use rand::RngCore;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub payload_base64: String,
    pub expires_at: i64,
    pub namespace: &'static str,
}
#[derive(Serialize)]
pub struct CredentialReceipt {
    pub credential_id: String,
    pub token: String,
    pub expires_at: i64,
}
pub(super) fn now() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unauthorized)?
            .as_secs(),
    )
    .map_err(|_| Error::Exhausted)
}
pub(super) fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| Error::Invalid("JSON"))
}
pub(super) struct Rights {
    pub(super) current: Vec<Grant>,
    pub(super) ceiling: Vec<Grant>,
    pub(super) kind: String,
    pub(super) can_mint: bool,
}
pub(super) struct Identity {
    pub(super) instance: String,
    pub(super) origin: String,
    pub(super) root: KeyPair,
}
impl Store {
    /// Local filesystem-authorized, one-time bootstrap. Never an HTTP endpoint.
    pub fn bootstrap(&mut self, ssh_public_key: &str, origin: &str) -> Result<()> {
        let key = ssh::public_key(ssh_public_key)?
            .to_openssh()
            .map_err(|_| Error::Invalid("SSH key"))?;
        let url = reqwest::Url::parse(origin).map_err(|_| Error::Invalid("origin"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(Error::Invalid("origin"));
        }
        if url.scheme() == "http"
            && !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
        {
            return Err(Error::Invalid("HTTPS origin required"));
        }
        let instance_id = uuid::Uuid::new_v4().to_string();
        let grants = json(&vec![
            Grant {
                actions: Action::ALL.to_vec(),
                selector: Selector::Prefix(String::new()),
            },
            Grant {
                actions: vec![
                    Action::AdminRead,
                    Action::AdminWrite,
                    Action::CredentialMint,
                    Action::CredentialList,
                    Action::CredentialRevoke,
                ],
                selector: Selector::Instance(instance_id.clone()),
            },
        ])?;
        let root = KeyPair::new();
        self.atomic(|store| {
            if store
                .connection
                .query_row("SELECT EXISTS(SELECT 1 FROM instance)", [], |r| {
                    r.get::<_, bool>(0)
                })?
            {
                return Err(Error::Conflict);
            }
            store.connection.execute(
                "INSERT INTO instance VALUES (1,?1,?2,?3)",
                params![
                    instance_id,
                    url.origin().ascii_serialization(),
                    root.private().to_bytes().as_slice()
                ],
            )?;
            store.connection.execute(
                "INSERT INTO principals(id,ssh_key,enabled,can_mint,grants) VALUES (?1,?2,1,1,?3)",
                params![uuid::Uuid::new_v4().to_string(), key, grants],
            )?;
            Ok(())
        })
    }
    pub(super) fn identity(&self) -> Result<Identity> {
        let (id, origin, bytes): (String, String, Vec<u8>) = self
            .connection
            .query_row(
                "SELECT id,origin,issuer_key FROM instance WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(Error::Unauthorized)?;
        let key = PrivateKey::from_bytes(&bytes, Algorithm::Ed25519)
            .map_err(|_| Error::DatabaseFormat)?;
        Ok(Identity {
            instance: id,
            origin,
            root: KeyPair::from(&key),
        })
    }
    pub(crate) fn principal_id(&self, bearer: &str) -> Result<String> {
        let identity = self.identity()?;
        let verified = VerifiedToken::parse(bearer, identity.root.public())?;
        self.rights(&verified)?;
        if verified.instance != identity.instance {
            return Err(Error::Unauthorized);
        }
        Ok(verified.principal)
    }
    pub fn authenticate(&self, bearer: &str) -> Result<()> {
        let identity = self.identity()?;
        let verified = VerifiedToken::parse(bearer, identity.root.public())?;
        if verified.instance != identity.instance {
            return Err(Error::Unauthorized);
        }
        self.rights(&verified)?;
        Ok(())
    }
    pub fn configured_origin(&self) -> Result<String> {
        Ok(self.identity()?.origin)
    }
    pub fn challenge(&mut self, ssh_public_key: &str) -> Result<Challenge> {
        let key = ssh::public_key(ssh_public_key)?
            .to_openssh()
            .map_err(|_| Error::Unauthorized)?;
        let identity = self.identity()?;
        let time = now()?;
        let expires_at = time.checked_add(60).ok_or(Error::Exhausted)?;
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let payload = json(
            &serde_json::json!({"version":1,"instance":identity.instance,"origin":identity.origin,"public_key":key,"nonce":STANDARD.encode(nonce),"expires_at":expires_at,"challenge_id":challenge_id}),
        )?;
        self.atomic(|store| {
            store
                .connection
                .execute("DELETE FROM challenges WHERE expires_at<=?1", [time])?;
            let count: i64 =
                store
                    .connection
                    .query_row("SELECT count(*) FROM challenges", [], |r| r.get(0))?;
            if count >= 128 {
                return Err(Error::Busy);
            }
            store.connection.execute(
                "INSERT INTO challenges(id,ssh_key,payload,expires_at) VALUES (?1,?2,?3,?4)",
                params![challenge_id, key, payload, expires_at],
            )?;
            Ok(())
        })?;
        Ok(Challenge {
            challenge_id,
            payload_base64: STANDARD.encode(payload),
            expires_at,
            namespace: ssh::NAMESPACE,
        })
    }
    pub fn exchange(&mut self, challenge_id: &str, signature: &str) -> Result<CredentialReceipt> {
        let (key, payload, expires): (String, String, i64) = self
            .connection
            .query_row(
                "SELECT ssh_key,payload,expires_at FROM challenges WHERE id=?1",
                [challenge_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(Error::Unauthorized)?;
        if expires <= now()? {
            return Err(Error::Unauthorized);
        }
        if self.connection.execute("UPDATE challenges SET attempts=attempts+1 WHERE id=?1 AND expires_at>?2 AND attempts<5", params![challenge_id,now()?])? != 1 {
            return Err(Error::Unauthorized);
        }
        ssh::verify(&ssh::public_key(&key)?, payload.as_bytes(), signature)?;
        let identity = self.identity()?;
        self.atomic(|store| {
            let current = now()?;
            let (principal, ceiling): (String, String) = store
                .connection
                .query_row(
                    "SELECT id,grants FROM principals WHERE ssh_key=?1 AND enabled=1",
                    [&key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(Error::Unauthorized)?;
            if store.connection.execute(
                "DELETE FROM challenges WHERE id=?1 AND expires_at>?2",
                params![challenge_id, current],
            )? != 1
            {
                return Err(Error::Unauthorized);
            }
            store.issue_credential(
                &identity,
                &principal,
                &ceiling,
                "ssh_session",
                current + 900,
            )
        })
    }
    fn issue_credential(
        &mut self,
        identity: &Identity,
        principal: &str,
        ceiling: &str,
        kind: &str,
        expires: i64,
    ) -> Result<CredentialReceipt> {
        let id = uuid::Uuid::new_v4().to_string();
        let bearer = token::issue(&identity.root, principal, &id, &identity.instance)?;
        self.connection.execute("INSERT INTO credentials(id,principal_id,ceiling,kind,expires_at) VALUES (?1,?2,?3,?4,?5)", params![id,principal,ceiling,kind,expires])?;
        Ok(CredentialReceipt {
            credential_id: id,
            token: bearer,
            expires_at: expires,
        })
    }
    pub(super) fn rights(&self, verified: &VerifiedToken) -> Result<Rights> {
        let (current,ceiling,kind,expires,mint): (String,String,String,i64,bool) = self.connection.query_row(
            "SELECT p.grants,c.ceiling,c.kind,c.expires_at,p.can_mint FROM credentials c JOIN principals p ON p.id=c.principal_id WHERE c.id=?1 AND p.id=?2 AND p.enabled=1 AND c.revoked=0",
            params![verified.credential, verified.principal], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?.ok_or(Error::Unauthorized)?;
        if expires <= now()? {
            return Err(Error::Unauthorized);
        }
        Ok(Rights {
            current: serde_json::from_str(&current).map_err(|_| Error::DatabaseFormat)?,
            ceiling: serde_json::from_str(&ceiling).map_err(|_| Error::DatabaseFormat)?,
            kind,
            can_mint: mint,
        })
    }
    /// Token cryptography/checks run before the write lock. Current rights,
    /// expiry and lifecycle are rechecked in the same transaction as the command.
    pub fn authorized<T>(
        &mut self,
        bearer: &str,
        action: Action,
        id: Option<&StreamId>,
        name: &StreamName,
        command: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let identity = self.identity()?;
        let verified = VerifiedToken::parse(bearer, identity.root.public())?;
        self.rights(&verified)?;
        verified.check(
            action.as_str(),
            "stream",
            id.map_or("", StreamId::as_str),
            name.as_str(),
            &identity.instance,
            SystemTime::now(),
        )?;
        self.atomic(|store| {
            let Rights {
                current, ceiling, ..
            } = store.rights(&verified)?;
            if let Some(id) = id
                && store.stream(id)?.name != *name
            {
                return Err(Error::NotFound);
            }
            if !auth::permits(&current, &ceiling, action, id, name) {
                return Err(Error::Forbidden);
            }
            // Recheck time-sensitive attenuation after any SQLite lock wait.
            verified.check(
                action.as_str(),
                "stream",
                id.map_or("", StreamId::as_str),
                name.as_str(),
                &identity.instance,
                SystemTime::now(),
            )?;
            command(store)
        })
    }
    pub(super) fn can_delegate(
        &self,
        current: &[Grant],
        ceiling: &[Grant],
        grants: &[Grant],
    ) -> Result<bool> {
        for grant in grants {
            if let Selector::Stream(id) = &grant.selector {
                let stream = self.stream(&id.parse()?)?;
                if !grant.actions.iter().all(|action| {
                    auth::permits(current, ceiling, *action, Some(&stream.id), &stream.name)
                }) {
                    return Ok(false);
                }
            } else if !auth::permits_delegation(current, ceiling, std::slice::from_ref(grant)) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub fn mint(
        &mut self,
        bearer: &str,
        grants: &[Grant],
        lifetime_seconds: i64,
    ) -> Result<CredentialReceipt> {
        auth::validate_grants(grants)?;
        if !(1..=86400).contains(&lifetime_seconds) {
            return Err(Error::Invalid("credential lifetime"));
        }
        let identity = self.identity()?;
        let verified = VerifiedToken::parse(bearer, identity.root.public())?;
        if !verified.is_unattenuated() {
            return Err(Error::Forbidden);
        }
        verified.check(
            "credential.mint",
            "instance",
            &identity.instance,
            "",
            &identity.instance,
            SystemTime::now(),
        )?;
        self.atomic(|store| {
            let Rights {
                current,
                ceiling,
                kind,
                can_mint,
            } = store.rights(&verified)?;
            if kind != "ssh_session"
                || !can_mint
                || !auth::permits_instance(
                    &current,
                    &ceiling,
                    Action::CredentialMint,
                    &identity.instance,
                )
                || !store.can_delegate(&current, &ceiling, grants)?
            {
                return Err(Error::Forbidden);
            }
            let max_lifetime: i64 = store.connection.query_row(
                "SELECT max_api_lifetime_seconds FROM auth_policy WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            if lifetime_seconds > max_lifetime {
                return Err(Error::Invalid("credential lifetime"));
            }
            store.issue_credential(
                &identity,
                &verified.principal,
                &json(&grants)?,
                "api",
                now()? + lifetime_seconds,
            )
        })
    }
    pub fn revoke(&mut self, bearer: &str, credential_id: &str) -> Result<()> {
        let identity = self.identity()?;
        let verified = VerifiedToken::parse(bearer, identity.root.public())?;
        if !verified.is_unattenuated() {
            return Err(Error::Forbidden);
        }
        verified.check(
            "credential.revoke",
            "instance",
            &identity.instance,
            "",
            &identity.instance,
            SystemTime::now(),
        )?;
        self.atomic(|store| {
            let Rights {
                current, ceiling, ..
            } = store.rights(&verified)?;
            if !auth::permits_instance(
                &current,
                &ceiling,
                Action::CredentialRevoke,
                &identity.instance,
            ) {
                return Err(Error::Forbidden);
            }
            if store.connection.execute(
                "UPDATE credentials SET revoked=1 WHERE id=?1 AND (principal_id=?2 OR ?3)",
                params![
                    credential_id,
                    verified.principal,
                    auth::permits_instance(
                        &current,
                        &ceiling,
                        Action::AdminWrite,
                        &identity.instance
                    )
                ],
            )? != 1
            {
                return Err(Error::NotFound);
            }
            Ok(())
        })
    }
}
