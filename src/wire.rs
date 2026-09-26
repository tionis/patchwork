//! Exact wire counters and UTC timestamps; no floating-point coercion.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub mod usize_decimal {
    use super::*;
    pub fn serialize<S: Serializer>(value: &usize, s: S) -> Result<S::Ok, S::Error> {
        value.to_string().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
        let value = String::deserialize(d)?;
        let counter = value
            .parse::<crate::model::Position>()
            .map_err(serde::de::Error::custom)?;
        usize::try_from(counter.get()).map_err(serde::de::Error::custom)
    }
}
pub mod optional_decimal {
    use super::*;
    pub fn serialize<S: Serializer>(value: &Option<i64>, s: S) -> Result<S::Ok, S::Error> {
        value.map(|v| v.to_string()).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|v| {
                v.parse::<crate::model::Position>()
                    .map(|p| p.get())
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}
pub fn timestamp_ms(ms: i64) -> crate::Result<String> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|_| crate::Error::Exhausted)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| crate::Error::Exhausted)
}
pub fn timestamp<S: Serializer>(seconds: &i64, s: S) -> Result<S::Ok, S::Error> {
    let value = seconds
        .checked_mul(1000)
        .ok_or_else(|| serde::ser::Error::custom("timestamp overflow"))?;
    timestamp_ms(value)
        .map_err(serde::ser::Error::custom)?
        .serialize(s)
}
