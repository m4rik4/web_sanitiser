# Valutazione sperimentale

`benchmark.py` prende le quattro misure chieste dalla sezione 7 della traccia e
ne fa i grafici. Un file solo, piu' i dati grezzi che produce.

```bash
cargo build --release                    # le misure si prendono solo su release
pip install -r scripts/requirements.txt
python scripts/benchmark.py
```

| cosa misura | bullet della traccia |
|---|---|
| detection rate e falsi positivi contro `corpus/ground_truth.json` | Correctness |
| latenza per input in funzione della dimensione, throughput | Performance |
| curve di speed-up ed efficienza al crescere dei worker | Scalability |
| picco di memoria residente per dimensione e per worker | Resource usage |

Con `--origin` si aggiunge il confronto **con e senza fetch delle
sotto-risorse**, che richiede il container evil-origin:

```bash
docker start evil-origin
python scripts/benchmark.py --origin http://localhost:3100
```

Le rotte usate sono `/html/resource-count-bomb` e `/html/recursive-include`, e la
scelta non e' casuale: il crawl gira solo nel ramo HTML e parte dall'output *gia'
sanitizzato*, quindi una pagina i cui riferimenti ostili sono appena stati
rimossi non ha piu' niente da scaricare. Servono sotto-risorse sulla stessa
origine, che sopravvivono alla sanitizzazione perche' `localhost` e' in
`fetch_host_allowlist`.

Per queste due misure la policy del banco **devia dal default** su due campi,
allineandosi a `tests/evil_origin_test.rs`: `max_fetch_depth: 2` e
`max_total_fetch_bytes: 100 MiB`, quest'ultimo perche' a fermare il crawl sia il
tetto sul numero di richieste e non quello sui byte. **Va dichiarato nella
relazione**: i tempi del confronto non sono quelli della configurazione di
produzione.

Lo script riporta per ogni rotta quante sotto-risorse sono state davvero
scaricate (le azioni `fetch-subresource`, lo stesso criterio del test) e avvisa
quando sono zero. Quell'avviso significa che la rotta non esiste nel container
oppure che i suoi riferimenti sono stati rimossi prima del crawl: in entrambi i
casi la differenza fra le due policy misura il costo del controllo, non del
download, e il grafico direbbe una cosa falsa. Su `recursive-include` il numero
atteso e' 1: la pagina referenzia se stessa con lo stesso URL, quindi a chiudere
il ciclo e' il set dei gia' visitati, non il tetto di profondita'.

Altre opzioni: `--reps N` (ripetizioni per punto, default 5), `--only <misura>`
per rifare una misura sola, `--quick` per un giro veloce che serve a verificare
che la catena funzioni, non a misurare, `--bin <percorso>` se il binario non e'
in `target/release`.

Output: dati in `scripts/results.json`, figure in `scripts/figures/`, in PNG a 200 dpi.

## Come sono prese le misure

Ogni punto e' la **mediana** di `--reps` esecuzioni, con la prima scartata: dalla
seconda in poi gli input sono nella page cache, e si misura il tool invece del
disco. Si usa la mediana e non la media perche' i tempi hanno una coda lunga a
destra (lo scheduler, un processo che parte in background) e la media la insegue.

Il **tempo di parete include l'avvio del processo** e la scrittura degli output
ripuliti: e' la latenza che vede chi usa la cli. Per questo la latenza per input
si ricava da un lotto di copie diviso il numero di copie — su un file da 16 KiB
misurare una copia sola vorrebbe dire misurare l'avvio del processo. Nella
relazione va dichiarato.

Gli input per prestazioni, scalabilita' e memoria sono **pagine sintetiche
generate dallo script**: la ripetizione dello stesso blocco, con la stessa
proporzione di costrutti pericolosi a ogni dimensione. Serve a poter dire che
una curva sale perche' il file e' piu' grande, non perche' e' fatto in modo
diverso. Il batch per la scalabilita' e' fatto di file tutti uguali: con input
di dimensione molto diversa l'ultimo file lungo terrebbe occupato un worker a
coda gia' vuota, e la curva misurerebbe lo sbilanciamento del carico invece del
parallelismo del motore.

Il **picco di memoria** si campiona ogni 3 ms con psutil: un picco molto breve
puo' sfuggire, quindi e' una stima per difetto.

Prima delle misure definitive conviene togliere da `src/main.rs` i tre
`eprintln!` marcati `// DA RIMUOVERE`: stampano policy, sorgenti e l'intero
`Report` in formato `Debug`, e formattare quelle strutture costa tempo dentro il
processo misurato. Poi: portatile alla corrente, profilo prestazioni al massimo,
niente browser o IDE che indicizza, e `--reps 7` o piu' per i numeri che
finiscono nella relazione.

## File generati

`scripts/.synthetic/` e `scripts/.scratch/` sono usa-e-getta e sono in
`.gitignore`. `scripts/results.json` e `scripts/figures/` conviene committarli:
sono i dati e le figure citati dalla relazione.
