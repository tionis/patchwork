//! Typed allow-only policy. Token checks cannot add grants to either side of
//! the current-policy / immutable-issuance-ceiling intersection.
use crate::{
    Error, Result,
    model::{StreamId, StreamName},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "hook.manage")]
    HookManage,
    #[serde(rename = "kv.read")]
    KvRead,
    #[serde(rename = "kv.write")]
    KvWrite,
    #[serde(rename = "attachment.read")]
    AttachmentRead,
    #[serde(rename = "attachment.write")]
    AttachmentWrite,
    #[serde(rename = "stream.list")]
    StreamList,
    #[serde(rename = "stream.watch")]
    StreamWatch,
    #[serde(rename = "record.subscribe")]
    RecordSubscribe,
    #[serde(rename = "admin.read")]
    AdminRead,
    #[serde(rename = "admin.write")]
    AdminWrite,
    #[serde(rename = "credential.mint")]
    CredentialMint,
    #[serde(rename = "credential.list")]
    CredentialList,
    #[serde(rename = "credential.revoke")]
    CredentialRevoke,
    #[serde(rename = "stream.create")]
    StreamCreate,
    #[serde(rename = "stream.inspect")]
    StreamInspect,
    #[serde(rename = "stream.delete")]
    StreamDelete,
    #[serde(rename = "stream.config.read")]
    ConfigRead,
    #[serde(rename = "stream.config.write")]
    ConfigWrite,
    #[serde(rename = "metadata.read")]
    MetadataRead,
    #[serde(rename = "metadata.write")]
    MetadataWrite,
    #[serde(rename = "record.append")]
    RecordAppend,
    #[serde(rename = "record.read")]
    RecordRead,
}

impl Action {
    pub const ALL: [Self; 22] = [
        Self::HookManage,
        Self::KvRead,
        Self::KvWrite,
        Self::AttachmentRead,
        Self::AttachmentWrite,
        Self::StreamList,
        Self::StreamWatch,
        Self::RecordSubscribe,
        Self::AdminRead,
        Self::AdminWrite,
        Self::CredentialMint,
        Self::CredentialList,
        Self::CredentialRevoke,
        Self::StreamCreate,
        Self::StreamInspect,
        Self::StreamDelete,
        Self::ConfigRead,
        Self::ConfigWrite,
        Self::MetadataRead,
        Self::MetadataWrite,
        Self::RecordAppend,
        Self::RecordRead,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HookManage => "hook.manage",
            Self::KvRead => "kv.read",
            Self::KvWrite => "kv.write",
            Self::AttachmentRead => "attachment.read",
            Self::AttachmentWrite => "attachment.write",
            Self::StreamList => "stream.list",
            Self::StreamWatch => "stream.watch",
            Self::RecordSubscribe => "record.subscribe",
            Self::AdminRead => "admin.read",
            Self::AdminWrite => "admin.write",
            Self::CredentialMint => "credential.mint",
            Self::CredentialList => "credential.list",
            Self::CredentialRevoke => "credential.revoke",
            Self::StreamCreate => "stream.create",
            Self::StreamInspect => "stream.inspect",
            Self::StreamDelete => "stream.delete",
            Self::ConfigRead => "stream.config.read",
            Self::ConfigWrite => "stream.config.write",
            Self::MetadataRead => "metadata.read",
            Self::MetadataWrite => "metadata.write",
            Self::RecordAppend => "record.append",
            Self::RecordRead => "record.read",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Selector {
    Stream(String),
    Instance(String),
    /// Empty means all canonical names; nonempty prefixes end at a slash.
    Prefix(String),
}
impl Selector {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Instance(id) => {
                uuid::Uuid::parse_str(id).map_err(|_| Error::Invalid("instance ID"))?;
            }
            Self::Stream(id) => {
                id.parse::<StreamId>()?;
            }
            Self::Prefix(prefix) if !prefix.is_empty() => {
                prefix
                    .strip_suffix('/')
                    .ok_or(Error::Invalid("grant prefix"))?
                    .parse::<StreamName>()?;
            }
            Self::Prefix(_) => {}
        }
        Ok(())
    }
    fn matches(&self, id: Option<&StreamId>, name: &StreamName) -> bool {
        match self {
            Self::Instance(_) => false,
            Self::Stream(expected) => id.is_some_and(|id| id.as_str() == expected),
            Self::Prefix(prefix) => name.as_str().starts_with(prefix),
        }
    }
    /// Prove containment over all possible resources, not just existing rows.
    fn contains(&self, child: &Self) -> bool {
        match (self, child) {
            (Self::Stream(a), Self::Stream(b)) | (Self::Instance(a), Self::Instance(b)) => a == b,
            (Self::Prefix(a), Self::Prefix(b)) => b.starts_with(a),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub actions: Vec<Action>,
    pub selector: Selector,
}
impl Grant {
    pub fn validate(&self) -> Result<()> {
        if self.actions.is_empty() || self.actions.len() > Action::ALL.len() {
            return Err(Error::Invalid("grant actions"));
        }
        self.selector.validate()
    }
}

pub fn validate_grants(grants: &[Grant]) -> Result<()> {
    if grants.len() > 128 {
        return Err(Error::Invalid("grant count"));
    }
    for grant in grants {
        grant.validate()?;
    }
    Ok(())
}

/// Credentials that may travel in a URL must not be able to do damage if the
/// URL leaks: one purpose (publish, or read/subscribe), only stream-data
/// actions, and explicit streams or a non-empty prefix, never the instance.
pub fn validate_url_grants(grants: &[Grant]) -> Result<()> {
    if grants.is_empty() || grants.len() > 16 {
        return Err(Error::Invalid("url credential grants"));
    }
    let (mut append, mut read) = (false, false);
    for grant in grants {
        for action in &grant.actions {
            match action {
                Action::RecordAppend => append = true,
                Action::RecordRead | Action::RecordSubscribe => read = true,
                _ => return Err(Error::Invalid("url credential action")),
            }
        }
        match &grant.selector {
            Selector::Stream(_) => {}
            Selector::Prefix(prefix) if !prefix.is_empty() => {}
            _ => return Err(Error::Invalid("url credential selector")),
        }
    }
    if append && read {
        return Err(Error::Invalid("url credential purpose"));
    }
    Ok(())
}

pub fn permits(
    current: &[Grant],
    ceiling: &[Grant],
    action: Action,
    id: Option<&StreamId>,
    name: &StreamName,
) -> bool {
    let matches = |grants: &[Grant]| {
        grants.iter().any(|g| {
            g.validate().is_ok() && g.actions.contains(&action) && g.selector.matches(id, name)
        })
    };
    matches(current) && matches(ceiling)
}

/// Conservative delegation proof. Exact IDs under prefix grants require a
/// separate, current resource lookup; this function never guesses their names.
pub fn permits_delegation(current: &[Grant], ceiling: &[Grant], requested: &[Grant]) -> bool {
    if validate_grants(requested).is_err() {
        return false;
    }
    requested.iter().all(|child| {
        child.actions.iter().all(|action| {
            let covers = |grants: &[Grant]| {
                grants.iter().any(|parent| {
                    parent.validate().is_ok()
                        && parent.actions.contains(action)
                        && parent.selector.contains(&child.selector)
                })
            };
            covers(current) && covers(ceiling)
        })
    })
}

pub mod ssh;
pub mod token;

pub fn permits_instance(
    current: &[Grant],
    ceiling: &[Grant],
    action: Action,
    instance: &str,
) -> bool {
    let matches = |grants: &[Grant]| {
        grants.iter().any(|g| {
            g.actions.contains(&action)
                && matches!(&g.selector, Selector::Instance(id) if id == instance)
        })
    };
    matches(current) && matches(ceiling)
}
