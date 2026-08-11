//! tipo di errore unico per tutto il crate
//!
//! l'input non è fidato, quindi il tool non deve mai andare in panic: ogni
//! fallimento diventa un valore `Result` che il chiamante è obbligato a gestire
//!
//! `Display` e `Error` sono scritti a mano invece di usare una libreria come
//! `thiserror`, così il modello di errore resta tutto visibile qui dentro

use std::fmt;

/// scorciatoia per non ripetere ovunque il tipo di errore
pub type Result<T> = std::result::Result<T, SanitiserError>;

/// tutti i modi in cui l'elaborazione di un input può fallire
#[derive(Debug)]
pub enum SanitiserError {
    /// errore di i/o sul file system
    Io(std::io::Error),
    /// url malformato o non interpretabile
    InvalidUrl(String),
    /// lo scaricamento da rete non è riuscito
    Fetch(String),
    /// richiesta fermata dalla guard ssrf: punta a un indirizzo interno
    SsrfBlocked(String),
    /// configurazione o report che non si riescono a leggere o scrivere
    Config(String),
    /// l'input sfora un limite dichiarato: dimensione, tempo, entità xml
    BudgetExceeded(String),
    /// contenuto respinto in blocco dalla policy
    Refused(String),
    /// errore nel parsing o nella riscrittura del documento
    Parse(String),
}

impl fmt::Display for SanitiserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SanitiserError::Io(e) => write!(f, "errore di I/O: {e}"),
            SanitiserError::InvalidUrl(s) => write!(f, "URL non valido: {s}"),
            SanitiserError::Fetch(s) => write!(f, "errore di fetch: {s}"),
            SanitiserError::SsrfBlocked(s) => write!(f, "richiesta bloccata (SSRF): {s}"),
            SanitiserError::Config(s) => write!(f, "errore di configurazione: {s}"),
            SanitiserError::BudgetExceeded(s) => write!(f, "budget superato: {s}"),
            SanitiserError::Refused(s) => write!(f, "contenuto rifiutato: {s}"),
            SanitiserError::Parse(s) => write!(f, "errore di parsing: {s}"),
        }
    }
}

impl std::error::Error for SanitiserError {
    /// espone l'errore originale, così chi legge può risalire alla causa vera
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SanitiserError::Io(e) => Some(e),
            _ => None,
        }
    }
}

// conversioni automatiche: grazie a queste si può usare `?` sugli errori delle
// librerie esterne, senza mapparli a mano ogni volta
impl From<std::io::Error> for SanitiserError {
    fn from(e: std::io::Error) -> Self {
        SanitiserError::Io(e)
    }
}
impl From<serde_json::Error> for SanitiserError {
    fn from(e: serde_json::Error) -> Self {
        SanitiserError::Config(e.to_string())
    }
}
impl From<url::ParseError> for SanitiserError {
    fn from(e: url::ParseError) -> Self {
        SanitiserError::InvalidUrl(e.to_string())
    }
}
impl From<reqwest::Error> for SanitiserError {
    fn from(e: reqwest::Error) -> Self {
        SanitiserError::Fetch(e.to_string())
    }
}
