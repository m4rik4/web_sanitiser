//! ciclo del singolo worker-thread e lavorazione di un input

use crate::engine::{Statistics, WorkerContext};
use crate::input::{file, Source, network};
use crate::report::{Action, JobReport};
use crate::policy::{SanitiserPolicy, rules};
use crate::error::SanitiserError;
use crate::parser::{sanitise_css, sanitise_html};
use std::collections::{VecDeque, HashSet};
use std::path::Path;
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

/// traduce un errore di caricamento nell'esito del job: se abbiamo deciso noi di
/// non elaborarlo il job è `Refused`, se invece non ci siamo riusciti è `Error`
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

/// hash fnv-1a a 32 bit: dà a `write_output` un suffisso stabile per distinguere
/// output che finirebbero sullo stesso nome
fn short_hash(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5; // valore di partenza fissato da fnv
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193); // primo di fnv; `wrapping` perché si lavora modulo 2^32
    }
    h
}

/// scrive l'output sanitizzato nella directory indicata
///
/// il nome si costruisce in due modi, perché i due casi perdono informazione in
/// modo diverso:
///
/// - file locale: `file_name()` dà già il nome con la sua estensione, si perde solo
///   la directory, che conta unicamente fra input omonimi; il suffisso serve solo lì
/// - url: si perdono schema, porta e query, quindi url diversi collassano sullo
///   stesso nome e il suffisso serve sempre
///
/// in nessuno dei due rami il nome contiene separatori di percorso, quindi il path
/// traversal è escluso
fn write_output(
    dir: &Path,
    src: &Source,
    ambiguous_names: &HashSet<String>,
    ext: &str,
    data: &[u8],
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?; // crea anche le directory intermedie, senza fallire se esistono già
    let name = match src {
        Source::File(p) => {
            let name = p
                .file_name() // solo l'ultimo pezzo del percorso, mai un separatore
                .map(|n| n.to_string_lossy().to_string())
                .unwrap();
            if !ambiguous_names.contains(&name) {
                name
            } else {
                let h = short_hash(&p.to_string_lossy());
                let stem = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap();
                match p.extension() {
                    Some(e) => format!("{stem}-{h:08x}.{}", e.to_string_lossy()),
                    None => format!("{stem}-{h:08x}"),
                }
            }
        }
        Source::Url(u) => {
            let base = url::Url::parse(u)
                .ok()
                .map(|p| {
                    let host = p.host_str().unwrap_or("url").to_string();
                    let path = p.path().trim_matches('/').to_string();
                    format!("{host}_{path}")
                })
                .unwrap_or_else(|| "url".to_string());
            let safe: String = base
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }) // qui cadono anche i separatori
                .collect();
            let safe = safe.trim_matches('_'); // via gli underscore agli estremi, lasciati dal passo sopra
            let stem = if safe.is_empty() { "url" } else { safe };
            format!("{}-{:08x}.{ext}", stem, short_hash(u))
        }
    };
    std::fs::write(dir.join(name), data)
}

/// scrive l'output se è stata indicata una directory, restituendo la descrizione
/// del fallimento invece di scartarla: il job resta `Sanitised`, ma il report deve
/// dire che su disco quel file non c'è
fn try_write(
    out_dir: Option<&Path>,
    src: &Source,
    ambiguous_names: &HashSet<String>,
    ext: &str,
    data: &[u8],
) -> Option<String> {
    let dir = out_dir?; // senza directory non c'è niente da scrivere, né da segnalare
    write_output(dir, src, ambiguous_names, ext, data)
        .err()
        .map(|e| format!("output non scritto in {}: {e}", dir.display()))
}

/// estensione dedotta dal tipo sniffato e non da quello dichiarato, perché il file
/// salvato deve dire la verità su cosa contiene; `bin` quando lo sniffing non
/// riconosce niente
fn ext_for(sniffed: Option<&str>) -> &'static str {
    match sniffed {
        Some("image/png") => "png",
        Some("image/jpeg") => "jpg",
        Some("image/gif") => "gif",
        Some("image/webp") => "webp",
        Some("application/pdf") => "pdf",
        Some("application/zip") => "zip",
        Some("application/gzip") => "gz",
        Some("text/html") => "html",
        Some("application/xml") => "xml",
        _ => "bin",
    }
}

/// lavorazione di un singolo input, dal caricamento alla scrittura dell'output
///
/// i controlli che possono rifiutare stanno tutti prima della riscrittura, così su
/// un input pericoloso non si spende il lavoro di sanitizzarlo
pub fn process_one(src: &Source, ctx: &WorkerContext, rt: &Handle) -> JobReport {
    let policy: &SanitiserPolicy = &ctx.policy;
    let client = &ctx.client;
    let label = src.label();
    let kind = src.kind();
    let ambiguous_names: &HashSet<String> = &ctx.ambiguous_names;
    let out_dir = ctx.out_dir.as_deref();

    // cronometro per il budget di tempo per-input (traccia sez. 4); il tetto si
    // verifica ai checkpoint fra una fase e l'altra, quindi non interrompe una
    // singola operazione a metà ma impedisce che un input sfori il budget complessivo
    let started = Instant::now();

    // 1. caricamento: il file dal disco, l'url dal runtime async
    let (bytes, declared_mime) = match src {
        Source::File(path) => match file::read_file(path, policy.max_input_bytes) {
            Ok(loaded) => loaded,
            Err(e) => return fetch_error_report(label, kind, e),
        },
        Source::Url(url) => match rt.block_on(network::fetch(client, url, policy)) {
            Ok(loaded) => loaded,
            Err(e) => return fetch_error_report(label, kind, e),
        },
    };
    let bytes_in = bytes.len();

    // 2. budget di dimensione, difesa dos (traccia sez. 4); il tetto lo applicano
    //    già la lettura da disco e quella da rete, quindi qui è solo un secondo
    //    controllo, che costa un confronto
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

    // 6. sanitizzazione per tipo: l'html si riconosce anche dai magic bytes, il css solo da come è dichiarato
    if rules::is_html(declared_mime.as_deref(), sniffed) {
        // 6a. html: riscrittura strutturale
        let html = String::from_utf8_lossy(&bytes); // i byte non validi utf-8 diventano U+FFFD, non un errore
        match sanitise_html(&html, policy) {
            Ok((clean, mut html_actions)) => {
                actions.append(&mut html_actions); // `append` svuota il vettore di partenza, per questo è `mut`
                let bytes_out = clean.len();
                let write_err = try_write(out_dir, src, ambiguous_names, "html", clean.as_bytes());

                // la base su cui risolvere i riferimenti è l'url stesso, oppure un `file://` per i file
                // locali (traccia sez. 3); in quel caso i riferimenti relativi diventano `file://` e li
                // scarta `absolute_links`, quindi si seguono solo i link verso la rete
                if policy.fetch_subresources {
                    let base = match src {
                        Source::Url(u) => url::Url::parse(u).ok(),
                        Source::File(p) => std::fs::canonicalize(p) // `from_file_path` pretende un percorso assoluto
                            .ok()
                            .and_then(|abs| url::Url::from_file_path(abs).ok()),
                    };
                    if let Some(base) = base {
                        let mut sub = crate::input::subresource::crawl_subresources(
                            &base, &clean, policy, rt, client, started, // `clean`, non l'originale: i link tolti non si seguono
                        );
                        actions.append(&mut sub);
                    }
                }

                // il crawl ha appena fatto richieste di rete, dove il budget di tempo salta più facilmente
                if policy.time_budget_exceeded(started) {
                    return JobReport::refused(label, kind, bytes_in, "supera max_processing_ms");
                }

                JobReport::sanitised(label, kind, bytes_in, bytes_out, actions)
                    .with_error(write_err)
            }
            Err(e) => JobReport::errored(label, kind, e.to_string()),
        }
    } else if rules::is_css(declared_mime.as_deref()) {
        // 6b. css: `sanitise_css` non può fallire, quindi qui non c'è ramo d'errore
        let css = String::from_utf8_lossy(&bytes);
        let (clean, mut css_actions) = sanitise_css(&css);
        actions.append(&mut css_actions);
        let bytes_out = clean.len();
        let write_err = try_write(out_dir, src, ambiguous_names, "css", clean.as_bytes());

        JobReport::sanitised(label, kind, bytes_in, bytes_out, actions).with_error(write_err)
    } else {
        // 6c. tutto il resto passa senza riscritture, per questo `bytes_in` vale anche come `bytes_out`
        let write_err = try_write(out_dir, src, ambiguous_names, ext_for(sniffed), &bytes);

        JobReport::sanitised(label, kind, bytes_in, bytes_in, actions).with_error(write_err)
    }
}
