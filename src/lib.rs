#![forbid(unsafe_code)]
//! # web_sanitiser
//!
//! motore che ispeziona contenuto web non fidato (pagine html, risorse scaricate,
//! asset) e ne neutralizza le parti pericolose, producendo una versione ripulita
//! e un report json di tutto ciò che è stato modificato
//!
//! è una libreria a sé: la cli le sta sopra come guscio sottile, così il motore
//! resta riutilizzabile anche da altri programmi
//!
//! `forbid(unsafe_code)` vieta qualsiasi blocco `unsafe` nel crate, e lo fa
//! rispettare il compilatore

pub mod error;
pub mod report;
pub mod policy;

// api principali: si usano come web_sanitiser::Nome, senza passare dal modulo
// che le contiene
pub use error::{Result, SanitiserError};
pub use report::{Action, JobReport, JobStatus, Report};
pub use policy::SanitiserPolicy;