//! motore concorrente (traccia sez. 5.1): un pool di thread consuma una coda
//! condivisa e i report tornano al thread principale su un canale
//!
//! ogni primitiva è scelta sull'uso reale: `Arc` senza lock per ciò che nessuno
//! modifica, `Mutex` per la coda che invece tutti modificano, i tipi atomici per
//! i contatori, dove ogni incremento è indipendente dagli altri

pub mod scheduler;
mod worker;

pub use scheduler::run_sanitisation_pipeline;

use crate::policy::SanitiserPolicy;
use crate::report::{JobReport, JobStatus};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// tutto ciò che un worker riceve una volta e che poi non cambia più per l'intera
/// esecuzione
///
/// l'immutabilità è il criterio con cui questa struct è stata separata dal resto:
/// coda, canale e statistiche cambiano di continuo e restano fuori; qui invece
/// non scrive nessuno, quindi ogni worker se ne tiene una copia senza lock; copiarla
/// costa poco, perché i campi pesanti vengono condivisi invece che duplicati
#[derive(Clone)]
struct WorkerContext {
    pub policy: Arc<SanitiserPolicy>,
    pub client: reqwest::Client, // un solo pool di connessioni per tutta l'esecuzione
    pub ambiguous_names: Arc<HashSet<String>>, // nomi base che compaiono su più input e vanno distinti in uscita
    pub out_dir: Option<PathBuf>,
}

/// contatori globali dell'esecuzione, aggiornati da tutti i worker senza mutex
#[derive(Default)]
struct Statistics {
    pub sanitised: AtomicU64,
    pub refused: AtomicU64,
    pub errors: AtomicU64,
    pub actions: AtomicU64,
}

impl Statistics {
    /// `Ordering::Relaxed` basta perché gli incrementi sono indipendenti fra loro:
    /// non serve che i contatori siano coerenti l'uno con l'altro a metà corsa,
    /// serve solo che nessun incremento vada perso
    pub fn record(&self, report: &JobReport) {
        self.actions
            .fetch_add(report.actions.len() as u64, Ordering::Relaxed);
        match report.status {
            JobStatus::Sanitised => {
                self.sanitised.fetch_add(1, Ordering::Relaxed);
            }
            JobStatus::Refused => {
                self.refused.fetch_add(1, Ordering::Relaxed);
            }
            JobStatus::Error => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Action;

    #[test]
    fn each_status_increments_its_own_counter() {
        let stats = Statistics::default();
        stats.record(&JobReport::sanitised("a.html".into(), "file", 1, 1, vec![]));
        stats.record(&JobReport::refused("b.html".into(), "file", 1, "PDF con contenuto attivo"));
        stats.record(&JobReport::errored("c.html".into(), "file", "lettura fallita"));

        assert_eq!(stats.sanitised.load(Ordering::Relaxed), 1);
        assert_eq!(stats.refused.load(Ordering::Relaxed), 1);
        assert_eq!(stats.errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn actions_are_summed_across_jobs() {
        let stats = Statistics::default();
        let due = vec![
            Action::new("remove-script", "<script>", "inline", ""),
            Action::new("mime-mismatch", "content-type", "text/plain", "text/html"),
        ];
        stats.record(&JobReport::sanitised("a.html".into(), "file", 1, 1, due));
        stats.record(&JobReport::refused("b.html".into(), "file", 1, "sospetto XML bomb"));

        // il contatore cresce con le azioni di ogni job, qualunque sia il suo esito
        assert_eq!(stats.actions.load(Ordering::Relaxed), 2);
    }
}
