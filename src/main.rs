#![forbid(unsafe_code)]
//! front-end a riga di comando del web sanitiser
//!
//! legge gli argomenti, carica la policy, avvia la pipeline della libreria
//! `web_sanitiser` e stampa il report json; la logica di sanitizzazione non sta
//! qui, ma tutta nella libreria
//!
//! exit code restituiti:
//! - `0`: tutti gli input sono stati sanitizzati
//! - `1`: almeno un input è stato rifiutato in blocco
//! - `2`: errore d'uso, ad esempio argomenti mancanti o policy non caricabile
//!
//! `forbid(unsafe_code)` vieta qualsiasi blocco `unsafe` nel crate, e lo fa
//! rispettare il compilatore

use clap::Parser;
use std::path::PathBuf;
use std::println;
use std::process::ExitCode;
use std::sync::Arc;
use web_sanitiser::SanitiserPolicy;
use web_sanitiser::input::{classify_arg, file, Source};

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
    threads: usize, // inseriti in CLI per misurare la speed-up curves

    /// directory dove scrivere gli output ripuliti
    #[arg(short = 'o', long)]
    out_dir: Option<PathBuf>,

    /// file dove scrivere il report, senza questo finisce su stdout
    #[arg(short = 'r', long)]
    report: Option<PathBuf>,

    /// stampa informazioni sull'avanzamento su stderr
    #[arg(short = 'v', long)]
    verbose: bool,
}

// adattabilità del core richiesto dalla traccia nella sezione 4
fn default_threads() -> usize {
    std::thread::available_parallelism() // legge core disponibili dal SO
        .map(|n| n.get())// estrae valore numerico
        .unwrap_or(4) // usa 4 se fallisce
}

fn main() -> ExitCode {
    let args = Args::parse();

    // 1. policy dal modulo `policy`
    let policy = match SanitiserPolicy::load(args.config.as_deref()) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("Errore nel caricamento della policy: {e}");
            return ExitCode::from(2);
        }
    };

    println!("{:?}", policy); // DA RIMUOVERE
 
    // 2. set-up degli input: le directory trasformate in liste di file
    let mut sources: Vec<Source> = Vec::new();
    for arg in &args.inputs {
        match classify_arg(arg) {
            Source::File(path) if path.is_dir() => match file::expand_dir(&path) { // entra solo se è una directory
                Ok(files) => sources.extend(files.into_iter().map(Source::File)), // come fossero più push insieme nel vec
                Err(e) => eprintln!("Impossibile leggere la directory {}: {e}", path.display()),
            },
            other => sources.push(other), // entra con file singolo o altro
        }
    }
    if sources.is_empty() {
        eprintln!("Nessun input valido fornito.");
        return ExitCode::from(2);
    }

    let threads = if args.threads == 0 {
        default_threads()
    } else {
        args.threads
    };
    if args.verbose {
        eprintln!("Sanitizzo {} input con {} thread", sources.len(), threads);
    }

    println!("{:?}", sources); // DA RIMUOVERE

    ExitCode::SUCCESS
}
