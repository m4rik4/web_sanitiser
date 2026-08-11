//! ciclo del singolo worker-thread e lavorazione di un input

use crate::engine::{Statistics, WorkerContext};
use crate::input::{file, Source, network};
use crate::report::{Action, JobReport};
use crate::policy::{SanitiserPolicy, rules};
use crate::error::SanitiserError;
use std::collections::{VecDeque, HashSet};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;
use std::time::Instant;

type Queue = Arc<Mutex<VecDeque<Source>>>;

/// ciclo del worker: prende un job alla volta dalla coda finché non è vuota
pub fn run(
    queue: Queue,
    ctx: WorkerContext,
    stats: Arc<Statistics>,
    rt: Handle,
    tx: Sender<JobReport>,
) {
    loop {
        // sezione critica ridotta al minimo: si estrae un job e si rilascia
        // subito il lock, così gli altri thread non restano fermi mentre questo
        // lavora; sul lock avvelenato si recupera il dato invece di propagare il
        // panic, perché qui dentro c'è solo un `pop_front`
        let next = {
            let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
            q.pop_front()
        };
        let Some(src) = next else { break };

        let report = process_one(&src, &ctx, &rt);
        stats.record(&report);

        if tx.send(report).is_err() {
            break; // il destinatario non ascolta più, inutile continuare
        }
    }
}

/// traduce un errore di caricamento nell'esito del job: quando è la policy a dire
/// no il job è `Refused`, quando invece non siamo riusciti a leggere l'input è
/// `Error`
///
/// serve a uniformare le due sorgenti: un input oversize preso dalla rete deve
/// essere rifiutato come un file oversize letto dal disco
fn fetch_error_report(label: String, kind: &str, e: SanitiserError) -> JobReport {
    match e {
        SanitiserError::BudgetExceeded(_)
        | SanitiserError::Refused(_)
        | SanitiserError::SsrfBlocked(_) => JobReport::refused(label, kind, 0, e.to_string()),
        other => JobReport::errored(label, kind, other.to_string()),
    }
}

/// lavorazione di un singolo input
///
/// per ora arriva fino al content sniffing: un input può già essere rifiutato,
/// ma chi supera tutti i controlli esce con un errore, perché il modulo `parser`
/// non è ancora nel crate
pub fn process_one(src: &Source, ctx: &WorkerContext, rt: &Handle) -> JobReport {
    let policy: &SanitiserPolicy = &ctx.policy;
    let client = &ctx.client;
    let label = src.label();
    let kind = src.kind();
    // questi due non servono ancora: li usa la scrittura dell'output, alla fase 6
    let ambiguous_names: &HashSet<String> = &ctx.ambiguous_names;
    let out_dir = ctx.out_dir.as_deref();

    // cronometro per il budget di tempo per-input (traccia sez. 4); il tetto si
    // verifica ai checkpoint fra una fase e l'altra, quindi non interrompe una
    // singola operazione a metà ma impedisce che un input sfori il budget complessivo
    let started = Instant::now();

    // 1. caricamento: il file dal disco, l'url dal runtime async
    let (bytes, declared_mime) = match src {
        Source::File(path) => match file::read_file(path) {
            Ok(loaded) => loaded,
            Err(e) => return JobReport::errored(label, kind, e.to_string()),
        },
        Source::Url(url) => match rt.block_on(network::fetch(client, url, policy)) {
            Ok(loaded) => loaded,
            Err(e) => return fetch_error_report(label, kind, e),
        },
    };
    let bytes_in = bytes.len();

    // 2. budget di dimensione, difesa dos (traccia sez. 4); viene prima delle
    //    regole sul contenuto perché costa un confronto invece di una scansione
    if bytes_in > policy.max_input_bytes {
        return JobReport::refused(label, kind, bytes_in, "supera max_input_bytes");
    }

    // 3. il mime dichiarato annuncia uno script: chi riceve il file lo eseguirà
    //    per come è dichiarato e non per quello che contiene; una dichiarazione
    //    non si può ripulire, quindi l'unica risposta è rifiutare
    if policy.reject_active_types && rules::is_declared_active_script(declared_mime.as_deref()) {
        return JobReport::refused(label, kind, bytes_in, "tipo attivo dichiarato");
    }

    // 4. rifiuti duri: di questi non esiste una versione ripulita, quindi non si
    //    riscrivono ma si respingono
    if rules::detect_xml_bomb(&bytes, policy.max_xml_entity_expansions) {
        return JobReport::refused(label, kind, bytes_in, "sospetto XML bomb (Billion Laughs)");
    }
    if rules::image_too_large(&bytes, policy.max_image_pixels) {
        return JobReport::refused(label, kind, bytes_in, "immagine oltre il budget di pixel");
    }
    if rules::pdf_has_active_content(&bytes) {
        return JobReport::refused(label, kind, bytes_in, "PDF con contenuto attivo");
    }

    // 4-bis. checkpoint del budget di tempo
    if policy.time_budget_exceeded(started) {
        return JobReport::refused(label, kind, bytes_in, "supera max_processing_ms");
    }

    // 5. content sniffing: il mime dichiarato non è fidato, il tipo vero lo dicono
    //    i magic bytes (i primi byte del file, che ne identificano il formato);
    //    una discrepanza non è un rifiuto ma un'azione da riportare
    let sniffed = rules::sniff_mime(&bytes);
    let mut actions: Vec<Action> = Vec::new();
    if rules::mime_mismatch(declared_mime.as_deref(), sniffed) {
        actions.push(Action::new(
            "mime-mismatch",
            "content-type",
            declared_mime.clone().unwrap_or_default(),
            sniffed.unwrap_or("sconosciuto").to_string(),
        ));
    }

    // DA COMPLETARE: 6. sanitizzazione per tipo, che consegnerà `actions` al report
    let e = "Occorrono funzioni di supporto";
    JobReport::errored(label, kind, e.to_string())
}
