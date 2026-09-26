use crate::{Error, Result};
use biscuit_auth::{
    AuthorizerBuilder, AuthorizerLimits, Biscuit, KeyPair, PublicKey, UnverifiedBiscuit,
    builder::{date, fact, string},
};
use std::time::{Duration, SystemTime};

pub const MAX_TOKEN_BYTES: usize = 32 * 1024;
pub const MAX_BLOCKS: usize = 8;

fn limits() -> AuthorizerLimits {
    AuthorizerLimits {
        max_facts: 1000,
        max_iterations: 100,
        max_time: Duration::from_millis(50),
    }
}

pub fn issue(root: &KeyPair, principal: &str, credential: &str, instance: &str) -> Result<String> {
    Biscuit::builder()
        .fact(fact("principal", &[string(principal)]))
        .map_err(|_| Error::Unauthorized)?
        .fact(fact("credential", &[string(credential)]))
        .map_err(|_| Error::Unauthorized)?
        .fact(fact("issued_instance", &[string(instance)]))
        .map_err(|_| Error::Unauthorized)?
        .build(root)
        .map_err(|_| Error::Unauthorized)?
        .to_base64()
        .map_err(|_| Error::Unauthorized)
}

pub struct VerifiedToken {
    token: Biscuit,
    pub principal: String,
    pub credential: String,
    pub instance: String,
}
impl VerifiedToken {
    pub fn parse(encoded: &str, public: PublicKey) -> Result<Self> {
        if encoded.len() > MAX_TOKEN_BYTES {
            return Err(Error::Unauthorized);
        }
        let unverified =
            UnverifiedBiscuit::from_base64(encoded).map_err(|_| Error::Unauthorized)?;
        if unverified.block_count() > MAX_BLOCKS
            || unverified
                .external_public_keys()
                .iter()
                .any(Option::is_some)
        {
            return Err(Error::Unauthorized);
        }
        let token = unverified.verify(public).map_err(|_| Error::Unauthorized)?;
        let mut authorizer = AuthorizerBuilder::new()
            .set_limits(limits())
            .build(&token)
            .map_err(|_| Error::Unauthorized)?;
        // The evaluator limit constrains derivation. Also cap initial facts,
        // including authority/ambient facts, before any query or checks run.
        if authorizer.fact_count() > limits().max_facts as usize {
            return Err(Error::Unauthorized);
        }
        let (principal, credential, instance): (String, String, String) = authorizer.query_exactly_one(
            "identity($p, $c, $i) <- principal($p), credential($c), issued_instance($i) trusting authority"
        ).map_err(|_| Error::Unauthorized)?;
        Ok(Self {
            token,
            principal,
            credential,
            instance,
        })
    }
    pub fn is_unattenuated(&self) -> bool {
        self.token.block_count() == 1
    }
    pub fn check(
        &self,
        action: &str,
        kind: &str,
        id: &str,
        name: &str,
        instance: &str,
        now: SystemTime,
    ) -> Result<()> {
        if self.instance != instance {
            return Err(Error::Unauthorized);
        }
        let mut authorizer = AuthorizerBuilder::new()
            .set_limits(limits())
            .fact(fact("operation", &[string(action)]))
            .map_err(|_| Error::Unauthorized)?
            .fact(fact("resource", &[string(kind), string(id)]))
            .map_err(|_| Error::Unauthorized)?
            .fact(fact("resource_name", &[string(name)]))
            .map_err(|_| Error::Unauthorized)?
            .fact(fact("instance", &[string(instance)]))
            .map_err(|_| Error::Unauthorized)?
            .fact(fact("time", &[date(&now)]))
            .map_err(|_| Error::Unauthorized)?
            // Rust checked current policy and the immutable ceiling separately.
            .code("allow if true;")
            .map_err(|_| Error::Unauthorized)?
            .build(&self.token)
            .map_err(|_| Error::Unauthorized)?;
        if authorizer.fact_count() > limits().max_facts as usize {
            return Err(Error::Forbidden);
        }
        authorizer.authorize().map_err(|_| Error::Forbidden)?;
        Ok(())
    }
}

/// Append checks using typed parameter substitution; no issuer key or server
/// call is required and no check in the parent chain can be removed.
pub fn attenuate(
    encoded: &str,
    read_only: bool,
    stream: Option<&str>,
    prefix: Option<&str>,
    expires_at: Option<&str>,
) -> Result<String> {
    use biscuit_auth::{
        BlockBuilder,
        builder::{date, string},
    };
    use std::collections::HashMap;
    if encoded.len() > MAX_TOKEN_BYTES
        || (!read_only && stream.is_none() && prefix.is_none() && expires_at.is_none())
    {
        return Err(Error::Invalid("attenuation"));
    }
    let token = UnverifiedBiscuit::from_base64(encoded).map_err(|_| Error::Unauthorized)?;
    if token.block_count() >= MAX_BLOCKS {
        return Err(Error::Invalid("attenuation block limit"));
    }
    let mut block = BlockBuilder::new();
    if read_only {
        block=block.code("check if operation($op), [\"record.read\",\"record.subscribe\",\"stream.inspect\",\"stream.list\",\"stream.watch\",\"stream.config.read\",\"metadata.read\"].contains($op);").map_err(|_|Error::Invalid("attenuation"))?;
    }
    if let Some(id) = stream {
        id.parse::<crate::model::StreamId>()?;
        block = block
            .code_with_params(
                "check if resource(\"stream\", {id});",
                HashMap::from([("id".into(), string(id))]),
                HashMap::new(),
            )
            .map_err(|_| Error::Invalid("attenuation"))?;
    }
    if let Some(prefix) = prefix {
        crate::auth::Selector::Prefix(prefix.into()).validate()?;
        block = block
            .code_with_params(
                "check if resource_name($name), $name.starts_with({prefix});",
                HashMap::from([("prefix".into(), string(prefix))]),
                HashMap::new(),
            )
            .map_err(|_| Error::Invalid("attenuation"))?;
    }
    if let Some(expiry) = expires_at {
        let time =
            time::OffsetDateTime::parse(expiry, &time::format_description::well_known::Rfc3339)
                .map_err(|_| Error::Invalid("expiry"))?;
        let seconds = u64::try_from(time.unix_timestamp()).map_err(|_| Error::Invalid("expiry"))?;
        let deadline = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or(Error::Exhausted)?;
        block = block
            .code_with_params(
                "check if time($now), $now < {expiry};",
                HashMap::from([("expiry".into(), date(&deadline))]),
                HashMap::new(),
            )
            .map_err(|_| Error::Invalid("attenuation"))?;
    }
    let result = token
        .append(block)
        .map_err(|_| Error::Invalid("attenuation"))?
        .to_base64()
        .map_err(|_| Error::Invalid("attenuation"))?;
    if result.len() > MAX_TOKEN_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(result)
}
