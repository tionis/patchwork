//! Bounded, deterministic built-ins. Original ingress bytes remain immutable;
//! every size check and validator runs against the final candidate.
use crate::{Error, Result, model::StreamConfig};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Filter {
    UppercaseAscii,
    Prepend { data_base64: String },
    DropIfContains { data_base64: String },
    RejectIfContains { data_base64: String },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Validator {
    Utf8,
    Json,
    ContentType { value: String },
    MaxBytes { value: usize },
}
fn decode(s: &str) -> Result<Vec<u8>> {
    if s.len() > 16384 {
        return Err(Error::Invalid("pipeline literal"));
    }
    STANDARD
        .decode(s)
        .map_err(|_| Error::Invalid("pipeline base64"))
}
pub fn validate_config(config: &StreamConfig) -> Result<()> {
    if config.filters.len() > 16 || config.validators.len() > 16 {
        return Err(Error::Invalid("pipeline stage count"));
    }
    for filter in &config.filters {
        match filter {
            Filter::UppercaseAscii => {}
            Filter::Prepend { data_base64 }
            | Filter::DropIfContains { data_base64 }
            | Filter::RejectIfContains { data_base64 } => {
                let literal = decode(data_base64)?;
                if literal.len() > 4096 {
                    return Err(Error::Invalid("pipeline literal"));
                }
            }
        }
    }
    for validator in &config.validators {
        match validator {
            Validator::ContentType { value } => validate_content_type(value)?,
            Validator::MaxBytes { value } if *value > crate::store::MAX_RECORD_BYTES => {
                return Err(Error::Invalid("validator byte limit"));
            }
            _ => {}
        }
    }
    Ok(())
}
pub fn validate_content_type(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 255 || !value.bytes().all(|b| (32..=126).contains(&b)) {
        return Err(Error::Invalid("content type"));
    }
    Ok(())
}
pub fn evaluate(
    config: &StreamConfig,
    original: &[u8],
    content_type: &str,
) -> Result<Option<Vec<u8>>> {
    validate_content_type(content_type)?;
    if original.len() > config.max_record_bytes {
        return Err(Error::TooLarge);
    }
    let mut candidate = original.to_vec();
    let started = std::time::Instant::now();
    for filter in &config.filters {
        if started.elapsed() > std::time::Duration::from_millis(100) {
            return Err(Error::Busy);
        }
        match filter {
            Filter::UppercaseAscii => candidate.make_ascii_uppercase(),
            Filter::Prepend { data_base64 } => {
                let mut prefix = decode(data_base64)?;
                if prefix.len() + candidate.len() > config.max_record_bytes {
                    return Err(Error::TooLarge);
                }
                prefix.extend_from_slice(&candidate);
                candidate = prefix;
            }
            Filter::DropIfContains { data_base64 } | Filter::RejectIfContains { data_base64 } => {
                let pattern = decode(data_base64)?;
                if memchr::memmem::find(&candidate, &pattern).is_some() {
                    return if matches!(filter, Filter::DropIfContains { .. }) {
                        Ok(None)
                    } else {
                        Err(Error::Rejected)
                    };
                }
            }
        }
    }
    if candidate.len() > config.max_record_bytes {
        return Err(Error::TooLarge);
    }
    for validator in &config.validators {
        if started.elapsed() > std::time::Duration::from_millis(100) {
            return Err(Error::Busy);
        }
        match validator {
            Validator::Utf8 => {
                std::str::from_utf8(&candidate).map_err(|_| Error::Rejected)?;
            }
            Validator::Json => {
                serde_json::from_slice::<serde_json::Value>(&candidate)
                    .map_err(|_| Error::Rejected)?;
            }
            Validator::ContentType { value } if value != content_type => {
                return Err(Error::Rejected);
            }
            Validator::MaxBytes { value } if candidate.len() > *value => {
                return Err(Error::TooLarge);
            }
            _ => {}
        }
    }
    if started.elapsed() > std::time::Duration::from_millis(100) {
        return Err(Error::Busy);
    }
    Ok(Some(candidate))
}
