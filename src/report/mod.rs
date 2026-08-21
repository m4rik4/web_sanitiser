//! strutture dati del report (traccia sez. 3)
//!
//! di ogni azione di sanitizzazione teniamo traccia di quattro cose: la regola
//! scattata, dove è successo, cosa c'era prima e cosa c'è adesso; così il
//! risultato è verificabile da chi legge e non solo dal tool
//!
//! tutto è serializzabile in json, la scrittura vera è in `json_emitter`

pub mod json_emitter;

use serde::Serialize;

/// una singola modifica applicata a un input
#[derive(Debug, Clone, Serialize)]
pub struct Action {
    /// nome della regola che è scattata, ad esempio "remove-script"
    pub rule: String,
    /// punto del documento in cui è successo: tag, attributo o posizione
    pub location: String,
    /// il contenuto com'era prima, o una sua descrizione breve
    pub original: String,
    /// con cosa è stato sostituito, stringa vuota se è stato rimosso
    pub replacement: String,
}

impl Action {
    /// accetta qualsiasi cosa convertibile in stringa, per non appesantire i
    /// punti di chiamata sparsi nel crate
    pub fn new(
        rule: impl Into<String>,
        location: impl Into<String>,
        original: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        Action {
            rule: rule.into(),
            location: location.into(),
            original: original.into(),
            replacement: replacement.into(),
        }
    }
}

/// come è finita la lavorazione di un input
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    /// ripulito, con o senza modifiche applicate; se tutti gli input finiscono
    /// così la cli esce con `0`
    Sanitised,
    /// respinto in blocco perché sfora un limite o lo vieta la policy; ne basta
    /// uno per far uscire la cli con `1`
    Refused,
    /// non è stato possibile elaborarlo, ad esempio per un errore di lettura;
    /// non tocca l'exit code, un input fallito non fa fallire l'intera esecuzione
    Error,
}

/// esito della lavorazione di un singolo input
#[derive(Debug, Clone, Serialize)]
pub struct JobReport {
    /// percorso del file o url di partenza
    pub input: String,
    /// "file" oppure "url"
    pub kind: String,

    /// come è andata a finire
    pub status: JobStatus,

    /// byte letti in ingresso
    pub bytes_in: usize,
    /// byte prodotti in uscita, zero se non è stato prodotto nulla
    pub bytes_out: usize,

    /// tutto ciò che è stato rimosso, sostituito o segnalato, vuoto quando non c'era
    /// niente da fare
    pub actions: Vec<Action>,

    // i due campi qui sotto si escludono a vicenda e spariscono dal json quando
    // sono vuoti, così il report non si riempie di null
    /// perché l'input è stato respinto, presente solo con `JobStatus::Refused`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    /// cosa è andato storto: sempre presente con `JobStatus::Error`, oppure su un job
    /// riuscito quando la scrittura dell'output è fallita
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl JobReport {
    /// input ripulito: riporta quanto è entrato, quanto è uscito e cosa è stato
    /// modificato
    pub fn sanitised(
        input: String,
        kind: &str,
        bytes_in: usize,
        bytes_out: usize,
        actions: Vec<Action>,
    ) -> Self {
        JobReport {
            input,
            kind: kind.to_string(),
            status: JobStatus::Sanitised,
            bytes_in,
            bytes_out,
            actions,
            refusal_reason: None,
            error: None,
        }
    }

    /// input respinto: non produce output, ma il motivo del rifiuto resta scritto
    pub fn refused(input: String, kind: &str, bytes_in: usize, reason: impl Into<String>) -> Self {
        JobReport {
            input,
            kind: kind.to_string(),
            status: JobStatus::Refused,
            bytes_in,
            bytes_out: 0,
            actions: Vec::new(),
            refusal_reason: Some(reason.into()),
            error: None,
        }
    }

    /// input non portato a termine: i byte restano a zero anche se la lettura era
    /// riuscita, perché una lavorazione fallita non ha misure da riportare
    pub fn errored(input: String, kind: &str, error: impl Into<String>) -> Self {
        JobReport {
            input,
            kind: kind.to_string(),
            status: JobStatus::Error,
            bytes_in: 0,
            bytes_out: 0,
            actions: Vec::new(),
            refusal_reason: None,
            error: Some(error.into()),
        }
    }

    /// aggiunge un errore a un job riuscito, come una scrittura dell'output fallita;
    /// un `None` non cancella un errore già presente
    pub fn with_error(mut self, error: Option<String>) -> Self {
        if error.is_some() {
            self.error = error;
        }
        self
    }
}

/// quante modifiche ha richiesto un singolo input
#[derive(Debug, Clone, Serialize)]
pub struct InputActionCount {
    pub input: String,
    pub actions: u64,
}

/// riepilogo di una singola esecuzione, con tutti gli input che ne fanno parte
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub total_inputs: usize,
    pub sanitised: usize,
    pub refused: usize,
    pub errors: usize,
    pub total_actions: usize,

    /// quante modifiche per input, esclusi quelli che non ne hanno richieste
    pub actions_by_input: Vec<InputActionCount>,
    /// il dettaglio completo, un elemento per input
    pub jobs: Vec<JobReport>,
}

impl Report {
    /// monta il report finale a partire da conteggi già calcolati da chi ha
    /// eseguito la pipeline, invece di ricavarli qui
    pub fn assemble(
        jobs: Vec<JobReport>,
        sanitised: usize,
        refused: usize,
        errors: usize,
        total_actions: usize,
        actions_by_input: Vec<InputActionCount>,
    ) -> Self {
        Report {
            total_inputs: jobs.len(),
            sanitised,
            refused,
            errors,
            total_actions,
            actions_by_input,
            jobs,
        }
    }

    /// vero se almeno un input è stato respinto; è quello che fa uscire la cli
    /// con un codice diverso da zero
    pub fn any_refused(&self) -> bool {
        self.refused > 0
    }
}
