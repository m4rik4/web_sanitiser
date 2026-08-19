//! sezione di input: preleva file locali, alberi di directory e URL

pub mod file;
pub mod network;
pub mod subresource;

use std::path::PathBuf;

/// tipo di input da elaborare
#[derive(Debug)]
pub enum Source {
    File(PathBuf),
    Url(String),
}

impl Source {
    pub fn kind(&self) -> &'static str { // static così che la stringa resti indipendente dal self
        match self {
            Source::File(_) => "file",
            Source::Url(_) => "url",
        }
    }
    pub fn label(&self) -> String {
        match self {
            Source::File(p) => p.display().to_string(), // crea nuova stringa
            Source::Url(u) => u.clone(),
        }
    }
}

/// classifica argomento CLI come URL remoto o percorso locale
pub fn classify_arg(arg: &str) -> Source {
    if arg.starts_with("http://") || arg.starts_with("https://") {
        Source::Url(arg.to_string())
    } else {
        Source::File(PathBuf::from(arg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_recognised_by_scheme_everything_else_is_a_file() {
        assert!(matches!(classify_arg("http://esempio.test/a"), Source::Url(_)));
        assert!(matches!(classify_arg("https://esempio.test/a"), Source::Url(_)));
        assert!(matches!(classify_arg(r"C:\Users\tizio\pagina.html"), Source::File(_)));
        assert!(matches!(classify_arg("./corpus/benign/simple.html"), Source::File(_)));
    }
}