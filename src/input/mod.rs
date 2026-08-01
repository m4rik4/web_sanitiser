//! sezione di input: preleva file locali, alberi di directory e URL

pub mod file;

use std::path::PathBuf;

/// tipo di input da elaborare
#[derive(Debug)]
pub enum Source {
    File(PathBuf),
    Url(String),
}

/// classifica argomento CLI come URL remoto o percorso locale
pub fn classify_arg(arg: &str) -> Source {
    if arg.starts_with("http://") || arg.starts_with("https://") {
        Source::Url(arg.to_string())
    } else {
        Source::File(PathBuf::from(arg))
    }
}
