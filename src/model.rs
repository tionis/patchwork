use std::{fmt, str::FromStr};

use crate::{Error, Result};

macro_rules! counter {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
        pub struct $name(i64);

        impl $name {
            pub const ZERO: Self = Self(0);
            pub fn new(value: i64) -> Result<Self> {
                if value < 0 {
                    return Err(Error::Invalid(stringify!($name)));
                }
                Ok(Self(value))
            }
            pub fn get(self) -> i64 {
                self.0
            }
            pub fn next(self) -> Result<Self> {
                self.0.checked_add(1).map(Self).ok_or(Error::Exhausted)
            }
        }
        impl FromStr for $name {
            type Err = Error;
            fn from_str(value: &str) -> Result<Self> {
                if value.is_empty()
                    || !value.bytes().all(|c| c.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(Error::Invalid(stringify!($name)));
                }
                Self::new(
                    value
                        .parse()
                        .map_err(|_| Error::Invalid(stringify!($name)))?,
                )
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}
counter!(Position);
counter!(Revision);

/// Opaque stable stream identity: canonical UUID v4 with a resource-kind prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamId(String);

impl StreamId {
    pub(crate) fn random() -> Self {
        Self(format!("str_{}", uuid::Uuid::new_v4()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for StreamId {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        let suffix = value
            .strip_prefix("str_")
            .ok_or(Error::Invalid("stream ID"))?;
        let id = uuid::Uuid::parse_str(suffix).map_err(|_| Error::Invalid("stream ID"))?;
        if id.get_version_num() != 4
            || id.get_variant() != uuid::Variant::RFC4122
            || id.hyphenated().to_string() != suffix
        {
            return Err(Error::Invalid("stream ID"));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamName(String);

impl StreamName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for StreamName {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > 240
            || !value.split('/').all(|part| {
                part.as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                    && part
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            })
        {
            return Err(Error::Invalid("stream name"));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug)]
pub struct Stream {
    pub id: StreamId,
    pub name: StreamName,
    pub head: Position,
    pub tail: Position,
    pub config_revision: Revision,
    pub metadata_revision: Revision,
}

/// Storage configuration. Pipelines, attachments and recovery requirements are
/// deliberately unavailable until their implementations can validate them.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    pub retention: Retention,
    pub max_record_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Retention {
    Infinite,
    None,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            retention: Retention::Infinite,
            max_record_bytes: crate::store::MAX_RECORD_BYTES,
        }
    }
}

impl StreamConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if !(1..=crate::store::MAX_RECORD_BYTES).contains(&self.max_record_bytes) {
            return Err(Error::Invalid("record limit"));
        }
        Ok(())
    }
}

/// Bounded JSON object, with no implicit object links or privileged fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata(String);

impl Default for Metadata {
    fn default() -> Self {
        Self("{}".to_owned())
    }
}

impl Metadata {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Metadata {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        if value.len() > 64 * 1024 {
            return Err(Error::TooLarge);
        }
        let parsed: serde_json::Value =
            serde_json::from_str(value).map_err(|_| Error::Invalid("metadata JSON"))?;
        if !parsed.is_object() {
            return Err(Error::Invalid("metadata object"));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Versioned<T> {
    pub revision: Revision,
    pub value: T,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Segment {
    pub start: Position,
    pub end: Position,
    pub record_count: i64,
    pub payload_bytes: i64,
    pub min_accepted_at_ms: i64,
    pub max_accepted_at_ms: i64,
    pub sealed: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Record {
    pub position: Position,
    pub payload: Vec<u8>,
    pub content_type: String,
    pub accepted_at_ms: i64,
}

#[derive(Debug)]
pub struct ReadPage {
    pub head: Position,
    pub tail: Position,
    pub next_position: Position,
    pub records: Vec<Record>,
}
