//! modulo delle policy dichiarative
//! la configurazione è deserializzabile da file JSON (serde)

pub mod config;
pub mod rules;

pub use config::{LinkAction, SanitiserPolicy};
