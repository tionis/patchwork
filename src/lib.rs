//! Internal storage primitives and the authenticated loopback prototype.
//! Raw Store methods are trusted internals; HTTP uses the authorized boundary.
pub mod auth;
pub mod cli;
pub mod config;
pub mod error;
pub mod http;
pub mod model;
pub mod store;

pub use error::{Error, Result};
