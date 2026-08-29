//! Test di integrazione contro il container 'evil-origin' (Docker, porta 3100)

// esecuzione: cargo test --test evil_origin_test -- --ignored

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use web_sanitiser::input::Source;
use web_sanitiser::policy::SanitiserPolicy;
use web_sanitiser::report::JobStatus;
use web_sanitiser::run_sanitisation_pipeline;

use std::path::PathBuf;

/// policy di testing: evil-origin è locale, quindi consentiamo esplicitamente il loopback (in produzione la guard SSRF lo bloccherebbe)
fn evil_policy() -> SanitiserPolicy {
    let mut p = SanitiserPolicy::default();
    p.allow_loopback = true;
    p.fetch_host_allowlist = vec!["localhost".into(), "127.0.0.1".into()];
    p
}

/// 'true' se qualcosa e' in ascolto sulla porta di evil-origin
// std::net per non passare dal sanitiser ->bug del sanitiser diverso da container spento
fn evil_origin_reachable() -> bool {
    "127.0.0.1:3100"
        .parse()
        .ok()
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok())
        .is_some()
}

/// esegue un singolo URL e ritorna lo status e le regole scattate
fn run_one(url: &str, policy: SanitiserPolicy) -> (JobStatus, Vec<String>) {
    assert!(
        evil_origin_reachable(),
        "evil-origin non raggiungibile su 127.0.0.1:3100.\n\
         Avvia il container prima dei test:  docker start evil-origin"
    );

    let sources = vec![Source::Url(url.into())];
    let report = run_sanitisation_pipeline(sources, Arc::new(policy), 1, Some(PathBuf::from("sanitised-out"))).unwrap();
    let job = &report.jobs[0];

    // a questo punto un errore di elaborazione non può piu' essere colpa dell'ambiente
    if job.status == JobStatus::Error {
        panic!(
            "errore di elaborazione su {url}: {}",
            job.error.clone().unwrap_or_else(|| "(nessun dettaglio)".into())
        );
    }

    println!("{:?}", report);

    (job.status.clone(), job.actions.iter().map(|a| a.rule.clone()).collect())
}

/// come run_one, ma per gli scenari che devono essere rifiutati: restituisce il motivo
fn refusal_reason(url: &str, policy: SanitiserPolicy) -> String {
    assert!(
        evil_origin_reachable(),
        "evil-origin non raggiungibile su 127.0.0.1:3100"
    );
    let sources = vec![Source::Url(url.into())];
    let report = run_sanitisation_pipeline(sources, Arc::new(policy), 1, None).unwrap();
    let job = &report.jobs[0];
    assert_eq!(
        job.status,
        JobStatus::Refused,
        "atteso Refused su {url}: {:?}",
        job.status
    );
    job.refusal_reason.clone().unwrap_or_default()
}

/// 'true' se la regola indica che un contenuto incorporato (iframe/object/embed) è stato rimosso o neutralizzato
fn is_embed_handled(rule: &str) -> bool {
    matches!(
        rule,
        "remove-active-embed"
            | "block-listed-host"
            | "block-ssrf-reference"
            | "neutralise-uri-scheme"
            | "flag-idn-homograph"
            | "flag-host-split"
    )
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn sanitises_script_tag_scenario() {
    let (status, rules) = run_one("http://localhost:3100/html/script-tag", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);
    assert!(rules.iter().any(|r| r == "remove-script"));
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn strips_inline_handler_scenario() {
    let (status, rules) = run_one("http://localhost:3100/html/inline-handler", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);
    assert!(
        rules.iter().any(|r| r == "strip-inline-handler"),
        "handler non rimossi: {rules:?}"
    );
    assert!(
        rules.iter().any(|r| r == "neutralise-uri-scheme"),
        "schemi non neutralizzati: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn removes_meta_refresh_scenario() {
    let (status, rules) = run_one("http://localhost:3100/html/meta-refresh", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);
    assert!(rules.iter().any(|r| r == "remove-meta-refresh"));
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn removes_active_iframe_scenario() {
    let (status, rules) = run_one("http://localhost:3100/html/iframe-embed", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);

    assert!(
        rules.iter().any(|r| is_embed_handled(r)),
        "iframe ostile non gestito, regole scattate: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn removes_object_embed_scenario() {
    // usa sia <object> sia <embed> -> rimuoverli tutti, quindi le azioni devono essere almeno due
    let (status, rules) = run_one("http://localhost:3100/html/object-embed", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);

    let n = rules.iter().filter(|r| is_embed_handled(r)).count();
    assert!(
        n >= 2,
        "attesi almeno due embed gestiti, trovati {n}: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn neutralises_data_uri_scenario() {
    // conteggio 4 dei data: presenti in data-uri di evil origin
    let (status, rules) = run_one("http://localhost:3100/html/data-uri", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);

    let n = rules
        .iter()
        .filter(|r| *r == "neutralise-uri-scheme")
        .count();
    assert!(
        n >= 4,
        "attese almeno 4 neutralizzazioni, trovate {n}: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn flags_idn_homograph_scenario() {
    let (status, rules) = run_one("http://localhost:3100/html/idn-homograph", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);
    assert!(
        rules.iter().any(|r| r == "flag-idn-homograph"),
        "omografo IDN non segnalato: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn flags_host_split_scenario() {
    let (status, rules) = run_one("http://localhost:3100/html/host-split", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);
    assert!(
        rules.iter().any(|r| r == "flag-host-split"),
        "confusione host/split non rilevata: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn blocks_ssrf_internal_reference() {
    // referenzia tre famiglie di indirizzi interni
    let (status, rules) = run_one(
        "http://localhost:3100/html/ssrf-internal-reference",
        evil_policy(),
    );
    assert_eq!(status, JobStatus::Sanitised);

    let n = rules
        .iter()
        .filter(|r| *r == "block-ssrf-reference")
        .count();
    assert!(
        n >= 3,
        "attesi almeno 3 riferimenti interni neutralizzati, trovati {n}: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn sanitises_malicious_css_scenario() {
    // lo scenario di evil origin elenca tre costrutti attivi
    let (status, rules) = run_one("http://localhost:3100/css/malicious", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);

    for atteso in [
        "neutralise-css-url",
        "remove-css-expression",
        "remove-css-import",
    ] {
        assert!(
            rules.iter().any(|r| r == atteso),
            "regola '{atteso}' mancante: {rules:?}"
        );
    }
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn refuses_xml_bomb_scenario() {
    let reason = refusal_reason("http://localhost:3100/mime/xml-bomb", evil_policy());
    assert!(reason.contains("XML bomb"), "motivo inatteso: {reason}");
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn refuses_declared_javascript_scenario() {
    let reason = refusal_reason(
        "http://localhost:3100/mime/text-disguised-as-javascript",
        evil_policy(),
    );
    assert!(
        reason.contains("tipo attivo dichiarato"),
        "motivo inatteso: {reason}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn refuses_gzip_bomb_scenario() {
    let reason = refusal_reason("http://localhost:3100/mime/gzip-bomb", evil_policy());
    assert!(
        reason.contains("non decodificabile"),
        "motivo inatteso: {reason}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn refuses_large_payload_scenario() {
    let reason = refusal_reason(
        "http://localhost:3100/download/large-payload",
        evil_policy(),
    );
    assert!(
        reason.contains("risposta oltre"),
        "motivo inatteso: {reason}"
    );
}