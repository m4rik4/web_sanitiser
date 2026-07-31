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
use std::process::ExitCode;

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
    threads: usize,

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

fn main() -> ExitCode {
    let args = Args::parse();

    // mostra come clap ha interpretato la riga di comando
    println!("{args:?}");

    ExitCode::SUCCESS
}
