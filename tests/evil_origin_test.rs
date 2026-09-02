//! Test di integrazione contro il container 'evil-origin' (Docker, porta 3100)

// esecuzione: cargo test --test evil_origin_test -- --ignored

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use web_sanitiser::{Source, SanitiserPolicy, JobStatus, run_sanitisation_pipeline};

use std::path::PathBuf;

// policy di testing: evil-origin è locale, quindi consentiamo esplicitamente il loopback (in produzione la guard SSRF lo bloccherebbe)
fn evil_policy() -> SanitiserPolicy {
    let mut p = SanitiserPolicy::default();
    p.allow_loopback = true;
    p.fetch_host_allowlist = vec!["localhost".into(), "127.0.0.1".into()];
    p
}

// 'true' se qualcosa e' in ascolto sulla porta di evil-origin
// std::net per non passare dal sanitiser -> bug del sanitiser diverso da container spento
fn evil_origin_reachable() -> bool {
    "127.0.0.1:3100"
        .parse()
        .ok()
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok())
        .is_some()
}

// esegue un singolo URL e ritorna lo status e le regole scattate
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

// come run_one, ma per gli scenari che devono essere rifiutati: restituisce il motivo
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

// 'true' se la regola indica che un contenuto incorporato (iframe/object/embed) è stato rimosso o neutralizzato
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

// il file pesa una ottantina di byte, quindi il rifiuto non può venire da un
// budget di dimensione: arriva dai pixel dichiarati nell'intestazione png
#[test]
#[ignore = "richiede il container evil-origin"]
fn refuses_huge_dimensions_scenario() {
    let reason = refusal_reason("http://localhost:3100/image/huge-dimensions", evil_policy());
    assert!(
        reason.contains("budget di pixel"),
        "motivo inatteso: {reason}"
    );
}

// per il tokenizzatore html5 `<scr<script>` è un elemento che si chiama
// `scr<script`, non uno script: zero azioni vuol dire nessun falso positivo
#[test]
#[ignore = "richiede il container evil-origin"]
fn handles_malformed_without_crash() {
    let (status, rules) = run_one("http://localhost:3100/html/malformed", evil_policy());
    assert_eq!(
        status,
        JobStatus::Sanitised,
        "l'HTML malformato deve essere sanificato, non produrre un errore"
    );
    assert!(
        rules.is_empty(),
        "nessuna regola dovrebbe scattare su questo payload: azioni={rules:?}"
    );
}

// gli indirizzi interni fuori dalla allow-list restano neutralizzati anche con
// il crawl acceso, perché il crawl parte dall'html già ripulito e i placeholder
// li scarta
#[test]
#[ignore = "richiede il container evil-origin"]
fn enabling_the_crawl_does_not_weaken_the_static_ssrf_defence() {
    let mut p = evil_policy();
    p.fetch_subresources = true;
    p.max_fetch_depth = 1;
    p.max_fetch_requests = 10;

    let (status, rules) = run_one("http://localhost:3100/html/ssrf-internal-reference", p);
    assert_eq!(status, JobStatus::Sanitised);
    assert!(
        rules.iter().any(|r| r == "block-ssrf-reference"),
        "riferimenti interni non neutralizzati: {rules:?}"
    );
}

// l'endpoint rimanda indietro gli header che ha ricevuto: la difesa sta già in
// `build_client`, che nasce senza cookie store, ma senza questo test nessuno se ne
// accorgerebbe se un domani qualcuno li abilitasse
//
// serve il contenuto della risposta e non le regole scattate, per questo l'output
// va in una directory temporanea invece di passare da `run_one`
#[test]
#[ignore = "richiede il container evil-origin"]
fn no_credentials_are_forwarded_to_the_remote() {
    assert!(
        evil_origin_reachable(),
        "evil-origin non raggiungibile su 127.0.0.1:3100.\n\
         Avvia il container prima dei test:  docker start evil-origin"
    );

    let dir = std::env::temp_dir().join(format!("ws-echo-headers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let sources = vec![Source::Url(
        "http://localhost:3100/html/echo-headers".into(),
    )];
    let report =
        run_sanitisation_pipeline(sources, Arc::new(evil_policy()), 1, Some(dir.clone())).unwrap();
    assert_eq!(report.jobs[0].status, JobStatus::Sanitised);

    let file = std::fs::read_dir(&dir)
        .expect("la directory di output non e' stata creata")
        .next()
        .expect("nessun file sanificato scritto")
        .expect("voce di directory illeggibile")
        .path();
    let body = std::fs::read_to_string(&file).expect("output non leggibile");

    assert!(
        body.contains("received-headers"),
        "contenuto inatteso, non e' la pagina di echo:\n{body}"
    );

    // l'endpoint elenca solo gli header che ha ricevuto, quindi se uno di questi
    // comparisse vorrebbe dire che il sanitiser lo ha inoltrato al server ostile
    let lower = body.to_ascii_lowercase();
    for header in ["cookie", "authorization", "proxy-authorization"] {
        assert!(
            !lower.contains(header),
            "l'header '{header}' e' stato inoltrato al server remoto:\n{body}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn sniffed_html_wins_over_declared_png() {
    let (status, rules) = run_one(
        "http://localhost:3100/mime/html-disguised-as-png",
        evil_policy(),
    );
    assert_eq!(status, JobStatus::Sanitised);
    assert!(
        rules.iter().any(|r| r == "mime-mismatch"),
        "sniff non registrato: {rules:?}"
    );
    assert!(
        rules.iter().any(|r| r == "remove-script"),
        "non sanificato come HTML: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn png_signature_wins_over_declared_octet_stream() {
    let (status, rules) = run_one(
        "http://localhost:3100/mime/png-magic-plus-html",
        evil_policy(),
    );
    assert_eq!(status, JobStatus::Sanitised);
    assert_eq!(
        rules,
        vec!["mime-mismatch".to_string()],
        "il poliglotta e' stato trattato come HTML invece che come immagine"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn refuses_pdf_with_active_content_over_the_network() {
    let reason = refusal_reason("http://localhost:3100/mime/scripted-pdf", evil_policy());
    assert!(
        reason.contains("PDF con contenuto attivo"),
        "motivo inatteso: {reason}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn revalidates_every_hop_and_sanitises_the_final_payload() {
    let (status, rules) = run_one(
        "http://localhost:3100/redirect/triple-hop-to-script-html",
        evil_policy(),
    );
    assert_eq!(status, JobStatus::Sanitised);
    assert!(
        rules.iter().any(|r| r == "remove-script"),
        "regole: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn aborts_the_fetch_when_the_timeout_budget_runs_out() {
    let mut p = evil_policy();
    p.fetch_timeout_ms = 1_000; // slowloris: senza abbassarlo si aspetterebbe il default
    let reason = refusal_reason("http://localhost:3100/download/slow-drip", p);
    assert!(reason.contains("timeout"), "motivo inatteso: {reason}");
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn content_disposition_cannot_escape_the_output_directory() {
    assert!(
        evil_origin_reachable(),
        "evil-origin non raggiungibile su 127.0.0.1:3100"
    );

    let dir = std::env::temp_dir().join(format!("ws-traversal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let sources = vec![Source::Url(
        "http://localhost:3100/download/path-traversal".into(),
    )];
    let report =
        run_sanitisation_pipeline(sources, Arc::new(evil_policy()), 1, Some(dir.clone())).unwrap();
    assert_eq!(report.jobs[0].status, JobStatus::Sanitised);

    // il contatore serve perché se l'attacco riuscisse il file finirebbe fuori da
    // `dir`, questa resterebbe vuota e il ciclo non avrebbe niente da controllare
    let mut found = 0;
    for entry in std::fs::read_dir(&dir).expect("directory di output assente") {
        let path = entry.unwrap().path();
        assert_eq!(
            path.parent(),
            Some(dir.as_path()),
            "file scritto fuori: {path:?}"
        );
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(!name.contains(".."), "nome con traversal: {name}");
        found += 1;
    }
    assert!(
        found > 0,
        "nessun file nella directory di output: o la scrittura e' fallita, o e' finito altrove"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn refuses_a_chain_longer_than_the_configured_limit() {
    let mut p = evil_policy();
    p.max_fetch_redirects = 1;
    let reason = refusal_reason(
        "http://localhost:3100/redirect/triple-hop-to-script-html",
        p,
    );
    assert!(reason.contains("redirect"), "motivo inatteso: {reason}");
}

// gli `<img>` non vengono marcati come interni, quindi il crawl parte davvero
#[test]
#[ignore = "richiede il container evil-origin"]
fn the_request_count_cap_stops_the_crawl() {
    let mut p = evil_policy();
    p.fetch_subresources = true;
    p.max_fetch_depth = 1;
    p.max_fetch_requests = 20;
    p.max_total_fetch_bytes = 100 * 1024 * 1024;

    let (status, rules) = run_one("http://localhost:3100/html/resource-count-bomb", p);
    assert_eq!(status, JobStatus::Sanitised);

    let fetched = rules.iter().filter(|r| *r == "fetch-subresource").count();
    assert!(fetched > 0, "il crawl non e' partito: {rules:?}");
    assert!(
        fetched <= 20,
        "il tetto non ha fermato il crawl: {fetched} richieste"
    );
    assert!(
        rules.iter().any(|r| r == "subresource-budget"),
        "il superamento del tetto va registrato nel report: {rules:?}"
    );
}

#[test]
#[ignore = "richiede il container evil-origin"]
fn pdf_signature_wins_over_declared_html() {
    let (status, rules) = run_one("http://localhost:3100/mime/pdf-served-as-html", evil_policy());
    assert_eq!(status, JobStatus::Sanitised);
    // che il documento non sia arrivato al rewriter si prova da `mime-mismatch` come
    // unica azione: una regola del rewriter vorrebbe dire che ci ha ingannati
    assert_eq!(
        rules,
        vec!["mime-mismatch".to_string()],
        "il PDF e' stato trattato come HTML: {rules:?}"
    );
}

// a spezzare il ciclo è `visited`, non `max_fetch_depth`: l'`<iframe>` lo toglie
// il rewriter, quindi al crawl arriva un link solo e al secondo incontro salta
//
// l'asserzione più importante è implicita: se il ciclo non terminasse, questo
// test non finirebbe mai
#[test]
#[ignore = "richiede il container evil-origin"]
fn the_recursive_include_cycle_terminates() {
    let mut p = evil_policy();
    p.fetch_subresources = true;
    p.max_fetch_depth = 2;
    p.max_fetch_requests = 10;
    p.max_total_fetch_bytes = 100 * 1024 * 1024;

    let (status, rules) = run_one("http://localhost:3100/html/recursive-include", p);
    assert_eq!(status, JobStatus::Sanitised);

    let fetched = rules.iter().filter(|r| *r == "fetch-subresource").count();
    assert_eq!(fetched, 1, "l'auto-referenza doveva essere scaricata una volta sola: {rules:?}");
}
