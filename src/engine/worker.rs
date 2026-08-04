//! ciclo del singolo worker-thread e lavorazione di un input

use crate::engine::{Statistics, WorkerContext};
use crate::input::Source;
use crate::report::JobReport;
use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;

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

/// lavorazione di un singolo input
///
/// per ora restituisce sempre un errore: i moduli che servono qui non sono
/// ancora nel crate
pub fn process_one(src: &Source, _ctx: &WorkerContext, _rt: &Handle) -> JobReport { // DA RIMUOVERE i _
    let label = src.label();
    let kind = src.kind();
    let e = "Occorrono funzioni di supporto";
    JobReport::errored(label, kind, e.to_string())
}
