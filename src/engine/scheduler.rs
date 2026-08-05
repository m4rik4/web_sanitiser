//! scheduler: prepara la coda, avvia il pool, raccoglie i report e li aggrega

use crate::engine::{worker, Statistics, WorkerContext};
use crate::error::{Result, SanitiserError};
use crate::input::{network, Source};
use crate::policy::SanitiserPolicy;
use crate::report::{JobReport, Report};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

/// esegue la pipeline su un batch di input, con `threads` worker
///
/// pool di thread, coda condivisa e canale per i risultati sono il modello di
/// concorrenza che la traccia chiede in sez. 5.1
pub fn run_sanitisation_pipeline(
    sources: Vec<Source>,
    policy: Arc<SanitiserPolicy>,
    threads: usize,
    out_dir: Option<PathBuf>,
) -> Result<Report> {
    // i worker sono thread di sistema perché il parsing è cpu-bound; le chiamate
    // di rete invece sono async e hanno bisogno di un runtime che le ospiti, in
    // cui i worker entrano con `block_on`
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all() // i/o di rete e timer
            .build()
            .map_err(|e| SanitiserError::Fetch(format!("creazione runtime tokio: {e}")))?,
    );

    // solo i nomi base che compaiono su più input avranno bisogno di un suffisso
    // in uscita; si contano qui perché subito dopo `sources` finisce nella coda
    let ambiguous_names: Arc<HashSet<String>> = {
        let mut seen: HashMap<String, usize> = HashMap::new();
        for s in &sources {
            if let Source::File(p) = s {
                if let Some(n) = p.file_name() {
                    // `to_string_lossy` dà un `Cow`, che presterebbe i byte senza copiarli;
                    // ma la chiave della mappa deve essere posseduta, quindi il `to_string`
                    // copia comunque
                    *seen.entry(n.to_string_lossy().to_string()).or_insert(0) += 1;
                }
            }
        }
        Arc::new(
            seen.into_iter()
                .filter(|(_, n)| *n > 1)
                .map(|(name, _)| name)
                .collect(),
        )
    };

    let queue: Arc<Mutex<VecDeque<Source>>> = Arc::new(Mutex::new(VecDeque::from(sources)));
    let stats = Arc::new(Statistics::default());
    let client = network::build_client(&policy)?; // uno per tutta l'esecuzione, non uno per richiesta

    let ctx = WorkerContext {
        policy,
        client,
        ambiguous_names,
        out_dir,
    };

    let (tx, rx) = mpsc::channel::<JobReport>();
    let n_workers = threads.max(1); // con 0 worker il canale non si chiuderebbe mai

    let mut handles = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let queue = queue.clone();
        let ctx = ctx.clone();
        let stats = stats.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            worker::run(queue, ctx, stats, rt.handle().clone(), tx);
        }));
    }

    // senza questo drop resta un mittente vivo e il ciclo su `rx` non finisce mai
    drop(tx);

    let mut jobs: Vec<JobReport> = Vec::new();
    for report in rx {
        jobs.push(report);
    }

    // prima si svuota il canale, poi si aspettano i thread: al contrario i worker
    // resterebbero bloccati su un `send` che nessuno legge
    for h in handles {
        let _ = h.join();
    }

    // DA COMPLETARE: l'aggregato si ricava dai `jobs`, dove ogni input compare
    // una volta sola; ordine per azioni decrescenti, a parità per nome
    let actions_by_input = Vec::new();

    Ok(Report::assemble(
        jobs,
        stats.sanitised.load(Ordering::Relaxed) as usize,
        stats.refused.load(Ordering::Relaxed) as usize,
        stats.errors.load(Ordering::Relaxed) as usize,
        stats.actions.load(Ordering::Relaxed) as usize,
        actions_by_input,
    ))
}
