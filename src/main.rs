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

fn main() {
    println!("web-sanitiser");
}
