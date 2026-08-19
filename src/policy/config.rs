//! configurazione delle policy, deserializzabile con serde

use crate::error::{Result, SanitiserError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Instant, Duration};

/// cosa fare con un link sospetto
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkAction {
    /// riscrivere il link neutralizzandone lo schema pericoloso
    Rewrite,
    /// sostituire con un placeholder di avviso
    Placeholder,
    /// rimuovere del tutto il link
    Remove,
}

/// policy di sanitizzazione. Ogni campo ha un valore di default con #[serde(default)].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)] //se durante la deserializzazione dovesse mancare qualche campo si usa il valore di default -> la struct deve implementare Default
pub struct SanitiserPolicy {
    // La traccia chiede budget "per-input time and size"
    /// budget massimo per input in byte
    pub max_input_bytes: usize,
    /// budget massimo di tempo per l'elaborazione di un singolo input
    pub max_processing_ms: u64,

    /// timeout per singolo fetch 
    pub fetch_timeout_ms: u64, //difesa Slowloris

    /// numero massimo di redirect seguiti
    pub max_fetch_redirects: usize, //difesa SSRF
    
    /// data: URI consentiti o negati (potenzialmente pericolosi)
    pub allow_data_uri: bool,
    
    /// consente loopback verso localhost (necessario per il docker di evil-origin)
    pub allow_loopback: bool, //solo per il testing
    /// blocca il fetch verso indirizzi privati
    pub block_private_addresses: bool, //difesa SSRF
    
    /// rifiuta le risposte con Content-Encoding compresso, senza fidarsi del rapporto di compressione
    pub reject_content_encoding: bool, //difesa decompression bomb

    /// rifiuta i contenuti il cui MIME dichiarato è un tipo di script attivo (text/javascript, ...)
    pub reject_active_types: bool, //difesa XSS, MIME confusion
    
    //HTML structural sanitisation
    /// host esplicitamente ammessi al fetch
    pub fetch_host_allowlist: Vec<String>, //difesa SSRF
    /// host da cui accettare `<script src=...>`
    pub script_src_allowlist: Vec<String>, 
    /// host fidati per contenuto incorporato (`<iframe>/<object>`)
    pub iframe_src_allowlist: Vec<String>,
    /// domini malware/bloccati
    pub domain_blocklist: Vec<String>,
    /// domini di tracker noti
    pub tracker_blocklist: Vec<String>,
    
    /// cosa fare con i link sospetti
    pub link_action: LinkAction, //URL and link inspection

    //difesa "huge-dimensions"
    /// numero massimo di pixel ammessi per un'immagine 
    pub max_image_pixels: u64, 
    /// soglia di espansione oltre la quale si sospetta un XML bomb
    pub max_xml_entity_expansions: usize,

    // sotto-risorse (opzionale) con limiti stretti
    /// abilita il download ricorsivo di CSS/JS/immagini referenziati
    pub fetch_subresources: bool,
    /// profondità massima di ricorsione
    pub max_fetch_depth: usize,
    /// budget cumulativo di byte totali
    pub max_total_fetch_bytes: usize,
    /// numero massimo di richieste di rete
    pub max_fetch_requests: usize,
}

impl Default for SanitiserPolicy {
    fn default() -> Self {
        SanitiserPolicy {
            max_input_bytes: 10 * 1024 * 1024, 
            max_processing_ms: 30_000,

            fetch_timeout_ms: 5_000,

            max_fetch_redirects: 3,

            allow_data_uri: false,

            allow_loopback: false,
            block_private_addresses: true,

            reject_content_encoding: true,

            reject_active_types: true,

            fetch_host_allowlist: Vec::new(),
            script_src_allowlist: Vec::new(),
            iframe_src_allowlist: Vec::new(),
            domain_blocklist: vec!["malware.test".into(), "evil.example".into()],
            tracker_blocklist: vec!["tracker.example".into(), "ads.example".into()],

            link_action: LinkAction::Placeholder,

            max_image_pixels: 40_000_000, 
            max_xml_entity_expansions: 1_000,
            
            fetch_subresources: false,
            max_fetch_depth: 1,
            max_total_fetch_bytes: 20 * 1024 * 1024, 
            max_fetch_requests: 20,
        }
    }
}

impl SanitiserPolicy {
    /// carica la policy da un file JSON, se il path è `None`, usa i default
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            None => Ok(Self::default()),
            Some(p) => {
                let text = std::fs::read_to_string(p)?;
                let policy: SanitiserPolicy = serde_json::from_str(&text)
                    .map_err(|e| SanitiserError::Config(format!("{}: {e}", p.display())))?;
                Ok(policy)
            }
        }
    }

    /// `true` se l'elaborazione iniziata in `started` ha superato il budget di tempo per-input 
    pub fn time_budget_exceeded(&self, started: Instant) -> bool {
        self.max_processing_ms > 0
            && started.elapsed() > Duration::from_millis(self.max_processing_ms)
    }

    /// 'true' se l'host è in una qualsiasi block-list (malware o tracker)
    pub fn is_host_blocked(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        self.domain_blocklist.iter().any(|d| host_matches(&h, d))
            || self.tracker_blocklist.iter().any(|d| host_matches(&h, d))
    }

    /// 'true' se uno '<script src=host>' proviene da un'origine in allow-list, uno script senza 'src' non è mai in allow-list
    // un 'src' relativo NON è ammesso dato che punta alla stessa origine del documento, che è per definizione non fidata
    pub fn script_src_allowed(&self, src: Option<&str>) -> bool {
        match src {
            None => false,
            Some(s) => match url::Url::parse(s) {
                Ok(u) => u
                    .host_str()
                    .map(|h| self.script_src_allowlist.iter().any(|a| a == h))
                    .unwrap_or(false),
                Err(_) => false,
            }
        }
    }

    /// 'true' se una sorgente di contenuto incorporato ('<iframe>/<object>/<embed>') è in 'iframe_src_allowlist'
    // come per gli script, un riferimento relativo non è ammesso
    pub fn embed_src_allowed(&self, src: &str) -> bool {
        match url::Url::parse(src.trim()) {
            Ok(u) => u
                .host_str()
                .map(|h| self.iframe_src_allowlist.iter().any(|a| a == h))
                .unwrap_or(false),
            Err(_) => false,
        }
    }
}

/// controllo di uguaglianza o sotto-dominio di un host rispetto ad una voce di block/tracker list
fn host_matches(host: &str, entry: &str) -> bool {
    let e = entry.to_ascii_lowercase();
    host == e || host.ends_with(&format!(".{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_partial_config_keeps_the_other_defaults() {
        // E' la promessa di #[serde(default)]: un file di configurazione parziale
        // sovrascrive solo i campi presenti. Se qualcuno togliesse l'attributo,
        // la deserializzazione fallirebbe invece di riempire i buchi.
        let p: SanitiserPolicy = serde_json::from_str(r#"{"max_input_bytes": 42}"#).unwrap();
        assert_eq!(p.max_input_bytes, 42);
        assert_eq!(p.max_processing_ms, SanitiserPolicy::default().max_processing_ms);
    }

    #[test]
    fn blocklist_matches_hosts_and_subdomains_only() {
        let p = SanitiserPolicy::default();
        assert!(p.is_host_blocked("malware.test"));
        assert!(p.is_host_blocked("cdn.malware.test"));      // sottodominio
        assert!(p.is_host_blocked("MALWARE.TEST"));          // maiuscole
        assert!(p.is_host_blocked("ads.example"));           // anche la lista tracker
        assert!(!p.is_host_blocked("notmalware.test"));      // suffisso senza il punto
        assert!(!p.is_host_blocked("malware.test.evil.it")); // prefisso, non dominio
    }

    #[test]
    fn only_absolute_allowlisted_sources_are_permitted() {
        let mut p = SanitiserPolicy::default();
        p.script_src_allowlist = vec!["cdn.fidato.test".into()];
        p.iframe_src_allowlist = vec!["video.fidato.test".into()];

        assert!(p.script_src_allowed(Some("https://cdn.fidato.test/app.js")));
        assert!(!p.script_src_allowed(None));                              // inline mai
        assert!(!p.script_src_allowed(Some("/locale/app.js")));            // relativo mai
        assert!(!p.script_src_allowed(Some("//cdn.fidato.test/app.js")));  // protocol-relative
        assert!(!p.script_src_allowed(Some("https://cdn.ostile.test/x.js")));

        assert!(p.embed_src_allowed("https://video.fidato.test/v"));
        assert!(!p.embed_src_allowed("/locale/v"));
    }

    #[test]
    fn time_budget_respects_the_configured_limit() {
        let mut policy = SanitiserPolicy::default();
        let started = Instant::now();
        std::thread::sleep(Duration::from_millis(10));

        // 0 disattiva il controllo, anche se del tempo e' passato.
        policy.max_processing_ms = 0;
        assert!(!policy.time_budget_exceeded(started), "con 0 il controllo e' disattivato");

        // Budget minimo: 10 ms trascorsi lo superano.
        policy.max_processing_ms = 1;
        assert!(policy.time_budget_exceeded(started));

        // Budget ampio: 10 ms su 30 s non lo scalfiscono.
        policy.max_processing_ms = 30_000;
        assert!(!policy.time_budget_exceeded(started));
    }
}