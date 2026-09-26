use super::{AppendReceipt, Store};
use crate::{
    Error, Result,
    auth::{Action, Selector},
    model::{Metadata, Retention, Revision, StreamConfig, StreamName},
    pipeline,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationTemplate {
    pub allow_append: bool,
    pub config: StreamConfig,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationRule {
    pub prefix: String,
    #[serde(flatten)]
    pub template: CreationTemplate,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationRules {
    pub default: CreationTemplate,
    pub rules: Vec<CreationRule>,
}
pub enum NameAppend {
    Retained {
        receipt: AppendReceipt,
        created: bool,
    },
    Live {
        stream: crate::model::Stream,
        payload: Vec<u8>,
        created: bool,
    },
    Dropped,
}
impl Store {
    pub fn creation_rules(&mut self, bearer: &str) -> Result<(Revision, CreationRules)> {
        self.instance_command(bearer, Action::AdminRead, |s, _| s.load_creation_rules())
    }
    fn load_creation_rules(&self) -> Result<(Revision, CreationRules)> {
        let (r, v): (i64, String) =
            self.connection
                .query_row("SELECT revision,value FROM creation_rules", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        Ok((
            Revision::new(r)?,
            serde_json::from_str(&v).map_err(|_| Error::DatabaseFormat)?,
        ))
    }
    pub fn replace_creation_rules(
        &mut self,
        bearer: &str,
        expected: Revision,
        rules: &CreationRules,
    ) -> Result<Revision> {
        if rules.rules.len() > 128 {
            return Err(Error::Invalid("creation rule count"));
        }
        rules.default.config.validate()?;
        let mut prefixes = std::collections::HashSet::new();
        for rule in &rules.rules {
            Selector::Prefix(rule.prefix.clone()).validate()?;
            rule.template.config.validate()?;
            if !prefixes.insert(&rule.prefix) {
                return Err(Error::Invalid("duplicate creation prefix"));
            }
        }
        self.instance_command(bearer, Action::AdminWrite, |s, _| {
            let next = expected.next()?;
            if s.connection.execute(
                "UPDATE creation_rules SET revision=?1,value=?2 WHERE revision=?3",
                params![
                    next.get(),
                    serde_json::to_string(rules).map_err(|_| Error::Invalid("creation rules"))?,
                    expected.get()
                ],
            )? != 1
            {
                return Err(Error::RevisionMismatch);
            }
            Ok(next)
        })
    }
    pub fn create_authorized(
        &mut self,
        bearer: &str,
        name: &StreamName,
        config: Option<&StreamConfig>,
        metadata: &Metadata,
    ) -> Result<crate::model::Stream> {
        self.authenticate(bearer)?;
        let (revision, rules) = self.load_creation_rules()?;
        let selected = rules
            .rules
            .iter()
            .filter(|r| name.as_str().starts_with(&r.prefix))
            .max_by_key(|r| r.prefix.len())
            .map_or(&rules.default, |r| &r.template);
        let config = config.unwrap_or(&selected.config);
        self.authorized(bearer, Action::StreamCreate, None, name, |s| {
            if s.load_creation_rules()?.0 != revision {
                return Err(Error::ConfigChanged);
            }
            s.create_stream_with(name, config, metadata)
        })
    }
    pub fn append_named(
        &mut self,
        bearer: &str,
        name: &StreamName,
        payload: &[u8],
        content_type: &str,
        key: Option<&str>,
    ) -> Result<NameAppend> {
        self.authenticate(bearer)?;
        match self.lookup_stream(name) {
            Ok(st) => {
                if self.config(&st.id)?.value.retention == Retention::None {
                    if key.is_some() {
                        return Err(Error::Invalid("live idempotency unavailable"));
                    }
                    return Ok(
                        match self.prepare_live(bearer, &st.id, payload, content_type)? {
                            Some(payload) => NameAppend::Live {
                                stream: st,
                                payload,
                                created: false,
                            },
                            None => NameAppend::Dropped,
                        },
                    );
                }
                return self
                    .append_authorized(bearer, &st.id, payload, content_type, key)
                    .map(|receipt| NameAppend::Retained {
                        receipt,
                        created: false,
                    });
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        let (revision, rules) = self.load_creation_rules()?;
        let selected = rules
            .rules
            .iter()
            .filter(|r| name.as_str().starts_with(&r.prefix))
            .max_by_key(|r| r.prefix.len())
            .map_or(&rules.default, |r| &r.template);
        if !selected.allow_append {
            return Err(Error::NotFound);
        }
        // Evaluate before creating anything. An intentional drop has no resource
        // or durable receipt. Creation+append permissions are still mandatory.
        let candidate = pipeline::evaluate(&selected.config, payload, content_type);
        self.authorized(bearer, Action::StreamCreate, None, name, |s| {
            s.authorized(bearer, Action::RecordAppend, None, name, |s| {
                if s.load_creation_rules()?.0 != revision {
                    return Err(Error::ConfigChanged);
                }
                if s.lookup_stream(name).is_ok() {
                    return Err(Error::ConfigChanged);
                }
                let Some(prepared) = candidate? else {
                    return Ok(NameAppend::Dropped);
                };
                let st = s.create_stream_with(name, &selected.config, &Metadata::default())?;
                if selected.config.retention == Retention::None {
                    if key.is_some() {
                        return Err(Error::Invalid("live idempotency unavailable"));
                    }
                    Ok(NameAppend::Live {
                        stream: st,
                        payload: prepared,
                        created: true,
                    })
                } else {
                    // The config is now fenced in this transaction. The common
                    // append implementation owns receipt and retained mutation.
                    let receipt =
                        s.append_authorized(bearer, &st.id, payload, content_type, key)?;
                    Ok(NameAppend::Retained {
                        receipt,
                        created: true,
                    })
                }
            })
        })
    }
}
