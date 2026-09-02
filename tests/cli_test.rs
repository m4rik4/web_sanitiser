//! test della pipeline sulle fasi che non richiedono il parser
//!
//! si passa dall'api della libreria invece che dal binario, perché la cli non
//! produce ancora file né un json pulito; qui contano lo stato del job e il
//! motivo del rifiuto, cioè le due cose che decide il motore

use std::path::PathBuf;
use std::sync::Arc;
use web_sanitiser::{Source, SanitiserPolicy, JobReport, JobStatus, run_sanitisation_pipeline};

/// esegue la pipeline su un file del corpus e restituisce il report del job
///
/// un solo input e un solo thread: così il report contiene esattamente un job e
/// non c'è ambiguità su quale leggere
fn run_file(rel: &str, policy: SanitiserPolicy) -> JobReport {
    // `CARGO_MANIFEST_DIR` è la cartella del Cargo.toml, che cargo passa al
    // compilatore: così il percorso non dipende da dove viene lanciato `cargo test`
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(rel);
    assert!(path.is_file(), "file di corpus mancante: {}", path.display());

    let sources = vec![Source::File(path)];
    let report = run_sanitisation_pipeline(sources, Arc::new(policy), 1, None)
        .expect("la pipeline non deve fallire in blocco");

    report
        .jobs
        .into_iter()
        .next()
        .expect("il report deve contenere il job dell'unico input")
}

/// verifica che l'input sia stato rifiutato e per quale controllo
///
/// il solo stato `Refused` non basterebbe: direbbe che è stato respinto senza
/// dire da cosa; un test che passa per il motivo sbagliato non protegge da niente
fn assert_refused(job: &JobReport, motivo: &str) {
    assert_eq!(
        job.status,
        JobStatus::Refused,
        "atteso Refused per {}, ottenuto {:?} ({:?})",
        job.input,
        job.status,
        job.error
    );

    let reason = job.refusal_reason.as_deref().unwrap_or("");
    assert!(
        reason.contains(motivo),
        "motivo atteso contenente {motivo:?}, ottenuto {reason:?}"
    );
}

// --- i quattro rifiuti che non passano dalla riscrittura ---

#[test]
fn xml_bomb_is_refused() {
    // lol5 arriva a 10.000 espansioni, dieci volte il tetto di default
    let job = run_file("malicious/xml-bomb.xml", SanitiserPolicy::default());
    assert_refused(&job, "XML bomb");
}

#[test]
fn oversized_image_is_refused() {
    // 33 byte che dichiarano un'immagine da 65535x65535: il tetto sui byte non
    // basta, le dimensioni vanno lette dall'intestazione
    let job = run_file("malicious/huge-image.png", SanitiserPolicy::default());
    assert_refused(&job, "pixel");
}

#[test]
fn pdf_with_active_content_is_refused() {
    let job = run_file("malicious/scripted-pdf.pdf", SanitiserPolicy::default());
    assert_refused(&job, "PDF");
}

#[test]
fn declared_javascript_is_refused() {
    // il file è locale, quindi il mime viene dall'estensione; `.js` diventa
    // application/javascript, che basta da solo a farlo rifiutare
    let job = run_file("malicious/active-script.js", SanitiserPolicy::default());
    assert_refused(&job, "tipo attivo");
}

// --- budget e ordine dei controlli ---

#[test]
fn oversized_input_is_refused() {
    let mut policy = SanitiserPolicy::default();
    policy.max_input_bytes = 10; // qualunque file del corpus lo supera

    let job = run_file("benign/simple.html", policy);
    assert_refused(&job, "max_input_bytes");
    assert!(job.bytes_in > 10, "bytes_in deve riportare la dimensione reale");
}

#[test]
fn size_budget_is_checked_before_content_rules() {
    // stesso file della bomba xml ma con un tetto minuscolo: deve scattare il
    // controllo sulla dimensione, non quello sul contenuto; sotto esame è
    // l'ordine delle fasi, non il singolo esito
    let mut policy = SanitiserPolicy::default();
    policy.max_input_bytes = 10;

    let job = run_file("malicious/xml-bomb.xml", policy);
    assert_refused(&job, "max_input_bytes");
}

#[test]
fn active_type_can_be_disabled_by_policy() {
    // controprova che il rifiuto arrivi dalla policy e non sia fisso nel codice:
    // con il flag spento lo stesso file supera quel controllo
    let mut policy = SanitiserPolicy::default();
    policy.reject_active_types = false;

    let job = run_file("malicious/active-script.js", policy);
    assert_ne!(
        job.status,
        JobStatus::Refused,
        "con reject_active_types disattivato il file non va rifiutato per quel motivo"
    );
}

// --- errori di caricamento ---

#[test]
fn missing_file_is_an_error_not_a_refusal() {
    // distinzione che il report deve mantenere: "non sono riuscito a leggerlo"
    // non è "l'ho esaminato e l'ho respinto"; solo il secondo pesa sull'exit code
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/non-esiste-affatto.html");
    let sources = vec![Source::File(path)];
    let report =
        run_sanitisation_pipeline(sources, Arc::new(SanitiserPolicy::default()), 1, None).unwrap();

    let job = &report.jobs[0];
    assert_eq!(job.status, JobStatus::Error);
    assert!(job.error.is_some(), "l'errore di I/O deve essere riportato");
}
