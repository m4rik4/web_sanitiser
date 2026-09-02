//! test sul corpus locale: esegue la pipeline su ogni file di corpus e verifica l'esito contro la ground truth
//! nessuna rete: gli input sono file locali

use std::path::PathBuf;
use std::sync::Arc;
use web_sanitiser::Source;
use web_sanitiser::SanitiserPolicy;
use web_sanitiser::JobStatus;
use web_sanitiser::run_sanitisation_pipeline;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

#[test]
fn corpus_matches_ground_truth() {
    let root = corpus_root();
    let manifest = std::fs::read_to_string(root.join("ground_truth.json"))
        .expect("corpus/ground_truth.json mancante");
    let gt: serde_json::Value = serde_json::from_str(&manifest).expect("ground_truth.json non valido");
    let entries = gt["entries"].as_array().expect("campo 'entries' assente");

    let policy = Arc::new(SanitiserPolicy::default());
    let mut failures: Vec<String> = Vec::new();

    for e in entries {
        let rel = e["path"].as_str().unwrap();
        let expected_status = e["expected_status"].as_str().unwrap();
        let path = root.join(rel);

        let sources = vec![Source::File(path)];
        let report = run_sanitisation_pipeline(sources, policy.clone(), 1, None).unwrap();
        let job = &report.jobs[0];

        let status_ok = match expected_status {
            "sanitised" => job.status == JobStatus::Sanitised,
            "refused" => job.status == JobStatus::Refused,
            "error" => job.status == JobStatus::Error,
            other => panic!("expected_status sconosciuto '{other}' per {rel}"),
        };
        if !status_ok {
            failures.push(format!(
                "{rel}: status atteso '{expected_status}', ottenuto {:?}",
                job.status
            ));
        }

        for r in e["expected_rules"].as_array().unwrap() {
            let rule = r.as_str().unwrap();
            if !job.actions.iter().any(|a| a.rule == rule) {
                let got: Vec<&String> = job.actions.iter().map(|a| &a.rule).collect();
                failures.push(format!("{rel}: regola attesa '{rule}' assente. Azioni: {got:?}"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "Disallineamenti rispetto alla ground truth:\n{}",
        failures.join("\n")
    );
}
