#![forbid(unsafe_code)]
//! front-end a riga di comando del web sanitiser
//!
//! legge gli argomenti, carica la policy, avvia la pipeline della libreria
//! `web_sanitiser`, scrive gli output ripuliti e stampa il report json; la
//! logica di sanitizzazione non sta qui, ma tutta nella libreria
//!
//! exit code restituiti:
//! - `0`: tutti gli input sono stati sanitizzati
//! - `1`: almeno un input è stato rifiutato in blocco
//! - `2`: errore d'uso, ad esempio argomenti mancanti o policy non caricabile
//!
//! `forbid(unsafe_code)` vieta qualsiasi blocco `unsafe` nel crate, e lo fa
//! rispettare il compilatore

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use clap::Parser;
use web_sanitiser::{run_sanitisation_pipeline, SanitiserPolicy};
use web_sanitiser::{classify_arg, file, Source};
use web_sanitiser::json_emitter;

/// argomenti della riga di comando; i doc-comment dei campi diventano il testo
/// che l'utente legge con `--help`
#[derive(Parser, Debug)]
#[command(version, about = "Rust Web Sanitiser - Final Project (PoliTo)")]
struct Args {
    /// file, directory o url da sanitizzare, ripetibile: -i a -i b
    #[arg(short = 'i', long = "input", required = true)]
    inputs: Vec<String>,

    /// file json con le policy, senza questo valgono quelle di default
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

    /// numero di thread, 0 per usarne quanti sono i core
    #[arg(short = 't', long, default_value_t = 0)]
    threads: usize, // configurabile per tracciare le curve di speed-up (traccia sez. 7)

    /// directory dove scrivere gli output ripuliti
    #[arg(short = 'o', long, default_value = "sanitised-out")]
    out_dir: PathBuf, // senza un default l'invocazione minima darebbe il report ma non i file ripuliti (traccia sez. 3)

    /// file dove scrivere il report, senza questo finisce su stdout
    #[arg(short = 'r', long)]
    report: Option<PathBuf>,

    /// stampa informazioni sull'avanzamento su stderr
    #[arg(short = 'v', long)]
    verbose: bool,
}

/// quanti thread usare quando l'utente non lo specifica
///
/// la traccia (sez. 4) chiede che il throughput scali con i core disponibili
fn default_threads() -> usize {
    std::thread::available_parallelism() // core visibili al processo
        .map(|n| n.get()) // da NonZeroUsize a usize
        .unwrap_or(4) // se il sistema non sa dirlo, un valore prudente
}

fn main() -> ExitCode {
    let args = Args::parse();

    // 1. policy: quella del file passato con -c, altrimenti quella di default
    let policy = match SanitiserPolicy::load(args.config.as_deref()) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("Errore nel caricamento della policy: {e}");
            return ExitCode::from(2);
        }
    };

    // 2. set-up degli input: le directory trasformate in liste di file
    let mut sources: Vec<Source> = Vec::new();
    for arg in &args.inputs {
        match classify_arg(arg) {
            Source::File(path) if path.is_dir() => match file::expand_dir(&path) { // una directory non è un input: lo sono i file dentro
                Ok(files) => sources.extend(files.into_iter().map(Source::File)), // ognuno entra come input a sé
                Err(e) => eprintln!("Impossibile leggere la directory {}: {e}", path.display()),
            },
            other => sources.push(other), // file e url si elaborano direttamente
        }
    }
    if sources.is_empty() {
        eprintln!("Nessun input valido fornito");
        return ExitCode::from(2);
    }

    let threads = if args.threads == 0 {
        default_threads()
    } else {
        args.threads
    };
    if args.verbose {
        eprintln!("\nSanitizzo {} input con {} thread", sources.len(), threads);
    }

    // 3. esecuzione della pipeline concorrente; per la libreria `out_dir` è opzionale, la cli invece passa sempre un valore
    let report = match run_sanitisation_pipeline(sources, policy, threads, Some(args.out_dir)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Errore della pipeline: {e}");
            return ExitCode::from(2);
        }
    };

    // 4. emissione del report json
    match &args.report {
        Some(path) => {
            if let Err(e) = json_emitter::write_to_file(&report, path) {
                eprintln!("Impossibile scrivere il report: {e}");
                return ExitCode::from(2);
            }
        }
        None => match json_emitter::to_json_string(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("Errore di serializzazione del report: {e}");
                return ExitCode::from(2);
            }
        },
    }

    if args.verbose {
        eprintln!(
            "\nFatto: {} sanitizzati, {} rifiutati, {} errori, {} azioni totali",
            report.sanitised, report.refused, report.errors, report.total_actions
        );
    }

    // 5. exit code
    if report.any_refused() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
