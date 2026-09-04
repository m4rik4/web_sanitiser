# WEB-SANITISER

Utility difensiva scritta in Rust che ispeziona contenuto web non fidato (pagine HTML, fogli di stile, immagini, documenti) ne neutralizza le parti pericolose e produce sia una versione ripulita sia un report JSON di tutto ciò che ha modificato.

Progetto finale di *Programmazione di Sistema*, Politecnico di Torino.

Il progetto è diviso in due crate, come chiede la sezione 6 della traccia: una **libreria** (`web_sanitiser`) che contiene il motore ed è riutilizzabile da altri programmi, e un **binario** (`web-sanitiser`) che è solo un strato sottile sopra di essa. La logica di sanitizzazione non sta mai nella CLI.

---

## Requisiti

| Cosa | Serve per | Come verificarlo |
|------|-----------|------------------|
| **Rust stabile** (edition 2021) | compilare ed eseguire | `rustc --version` |
| **Docker** | i test contro il container `evil-origin` | `docker --version` |
| **Python 3.9+** | la valutazione sperimentale (sez. 7) | `python --version` |

Rust si installa da [rustup.rs](https://rustup.rs). Docker e Python servono solo per i test avanzati e per i benchmark: per compilare e usare il tool basta Rust.

Nessuna dipendenza di sistema esterna: TLS è fornito da `rustls`, quindi non serve OpenSSL installato.

---

## Compilazione

```bash
git clone <url-del-repository>
cd web_sanitiser

cargo build                # build di sviluppo, con i controlli a runtime
cargo build --release      # build ottimizzata, obbligatoria per le misure
```

Il binario finisce in `target/debug/web-sanitiser` oppure `target/release/web-sanitiser`.

Per eseguirlo senza indicare il percorso:

```bash
cargo run -- --help
cargo run --release -- -i corpus/malicious
```

---

## Uso rapido

Sanitizzare una cartella di file locali:

```bash
cargo run --release -- -i corpus/malicious -o puliti -r report.json
```

Sanitizzare una pagina remota:

```bash
cargo run --release -- -i https://esempio.test/pagina.html -o puliti
```

Più input insieme, anche di tipo diverso:

```bash
cargo run --release -- -i corpus/benign -i corpus/malicious/xss-script-tag.html -i https://esempio.test/
```

Il report JSON, se non si indica `-r`, viene stampato su standard output.

---

## Riferimento della riga di comando

```
web-sanitiser [OPZIONI] -i <INPUT>...
```

| Opzione | Descrizione | Default |
|---------|-------------|---------|
| `-i`, `--input <INPUT>` | File, directory o URL da sanitizzare. **Ripetibile.** Le directory vengono espanse ricorsivamente | obbligatorio |
| `-c`, `--config <FILE>` | File JSON con le policy | policy integrata |
| `-t`, `--threads <N>` | Numero di worker. `0` significa "quanti sono i core" | `0` |
| `-o`, `--out-dir <DIR>` | Dove scrivere i contenuti ripuliti | `sanitised-out` |
| `-r`, `--report <FILE>` | Dove scrivere il report JSON | standard output |
| `-v`, `--verbose` | Informazioni sull'avanzamento su standard error | spento |
| `-h`, `--help` | Aiuto | |
| `-V`, `--version` | Versione | |

Un input che comincia con `http://` o `https://` è trattato come URL, tutto il resto come percorso locale.

### Exit code

| Codice | Significato |
|--------|-------------|
| `0` | tutti gli input sono stati sanitizzati |
| `1` | almeno un input è stato **rifiutato in blocco** |
| `2` | errore d'uso: argomenti mancanti, policy non caricabile, nessun input valido |

Il codice `1` non è un errore del programma: è il modo in cui la CLI segnala a uno script che qualcosa è stato respinto.

---

## Configurazione delle policy

Senza `-c` valgono i default definiti nel codice. `config/default_policy.json` li riproduce ed è il punto di partenza per scrivere una policy propria: un file parziale è valido, i campi assenti mantengono il valore predefinito.

```bash
cargo run --release -- -i corpus/malicious -c config/default_policy.json
```

I campi più rilevanti:

| Campo | Che cosa governa |
|-------|------------------|
| `max_input_bytes` | tetto sulla dimensione di un singolo input |
| `max_processing_ms` | tetto sul tempo di elaborazione per input, `0` disattiva |
| `fetch_timeout_ms` | timeout della singola richiesta HTTP |
| `max_fetch_redirects` | quanti redirect seguire |
| `link_action` | `rewrite`, `placeholder` o `remove` per i link sospetti |
| `allow_data_uri` | se ammettere i `data:` URI |
| `allow_loopback`, `block_private_addresses` | difesa SSRF |
| `fetch_host_allowlist` | host fidati, esentati dai controlli SSRF |
| `script_src_allowlist`, `iframe_src_allowlist` | origini da cui accettare script e contenuto incorporato |
| `domain_blocklist`, `tracker_blocklist` | domini da bloccare |
| `max_image_pixels`, `max_xml_entity_expansions` | difese contro immagini e XML bomb |
| `fetch_subresources` | scarica anche CSS, JS e immagini referenziati. **Spento per default** |
| `max_fetch_depth`, `max_total_fetch_bytes`, `max_fetch_requests` | i tre limiti del crawl |

---

## Che cosa produce

**I contenuti ripuliti**, nella directory indicata da `-o`. Il nome viene ricostruito in modo che non possa contenere separatori di percorso, quindi un output non può mai finire fuori da quella directory. L'estensione riflette il tipo **reale** rilevato, non quello dichiarato dal server.

**Il report JSON**, che per ogni input riporta esito, byte in ingresso e in uscita, e l'elenco delle azioni applicate.

Tre esiti possibili: **`sanitised`** (ripulito, con o senza modifiche), **`refused`** (respinto in blocco dalla policy) ed **`error`** (guasto tecnico, per esempio un file illeggibile).

Ci sono poi due chiavi opzionali compaiono solo quando servono: `refusal_reason` dice **perché** un input è stato respinto ed è presente solo sui rifiuti, `error` compare sui job falliti e su quelli riusciti la cui scrittura su disco non è andata a buon fine. Un job completato senza errori non contiene nessuno dei due campi.

`actions_by_input` è un riepilogo ordinato dal più problematico in giù, utile per capire a colpo d'occhio quale input ha richiesto più interventi senza scorrere tutti i job.


---

## Test

### Unità e integrazione

```bash
cargo test
```

Esegue i test di unità, che stanno dentro i moduli sorgente accanto al codice che provano, e i test di integrazione in `tests/`. Non serve rete né Docker.

Qualche variante utile:

```bash
cargo test --lib                     # solo i test di unità
cargo test --test corpus_test        # solo la verifica sul corpus
cargo test rules                     # solo i test il cui nome contiene "rules"
cargo test -- --nocapture            # mostra anche le stampe dei test
```

`tests/corpus_test.rs` esegue la pipeline su ogni campione di `corpus/` e confronta l'esito con `corpus/ground_truth.json`, che è la verità di riferimento etichettata a mano.

### Contro il container `evil-origin`

`tests/evil_origin_test.rs` verifica il comportamento del sanitiser contro un server ostile. Il server non fa parte del repository, ma viene distribuito separatamente. I test sono marcati `#[ignore]`, quindi vengono saltati da un normale `cargo test`.

Se si dispone dell'immagine Docker del server, è possibile creare il container con:

```bash
docker run -d -p 3100:3100 --name evil-origin evil-origin
```

Nelle sessioni successive, se il container è già stato creato, è sufficiente riavviarlo:

```bash
docker start evil-origin
docker ps
```

Per verificare che il server sia raggiungibile:

```bash
curl.exe -s http://localhost:3100/health
```

I test possono quindi essere eseguiti con:

```bash
cargo test --test evil_origin_test -- --ignored
```

Il catalogo degli scenari disponibili può essere visualizzato con:

```bash
curl -s http://localhost:3100/scenarios | jq
```

Se i test segnalano che `evil-origin` non è raggiungibile, verificare che il container sia in esecuzione.

---

## Nota sugli antivirus

`corpus/malicious/` contiene **campioni malevoli sintetici** (payload XSS, una XML bomb, un PDF con JavaScript, huge images) scritti da noi e necessari alla valutazione di correttezza richiesta dalla sezione 7 della traccia. Sono inerti: nessuno di essi è eseguibile, e servono solo a essere dati in pasto al sanitiser.

Un antivirus attivo può metterli in quarantena al momento del clone, oppure bloccare i binari di test appena compilati. Se `cargo test` fallisce con un errore di **accesso negato** (`os error 5`), va aggiunta un'esclusione sulla cartella `target/` del progetto.

---

## Valutazione sperimentale

Correttezza, prestazioni, scalabilità e uso di memoria sono misurate e prodotte da un unico script.

```bash
cargo build --release
pip install -r scripts/requirements.txt
python scripts/benchmark.py
```

| Opzione | Effetto | Default |
|---------|---------|---------|
| `--reps N` | ripetizioni per punto | `5` |
| `--origin <url>` | aggiunge il confronto con e senza fetch delle sotto-risorse | assente |
| `--only <misura>` | una sola misura: `correttezza`, `prestazioni`, `scalabilita`, `memoria` | tutte |
| `--quick` | corpus ridotto e due ripetizioni: prova la catena, non misura | spento |
| `--bin <percorso>` | binario da usare, se non è in `target/release` | automatico |


Il confronto **con e senza fetch delle sotto-risorse** richiede il container:

```bash
docker start evil-origin
python scripts/benchmark.py --origin http://localhost:3100
```

Dati grezzi in `scripts/results.json`, figure in `scripts/figures/`.

---

## Struttura del repository

```
src/
  lib.rs            superficie pubblica della libreria
  main.rs           front-end a riga di comando
  error.rs          tipi di errore del crate
  input/            astrazione sugli ingressi
    file.rs           lettura da disco ed espansione delle directory
    network.rs        fetch HTTP, guard SSRF, policy di redirect
    subresource.rs    crawl limitato delle sotto-risorse
  policy/
    config.rs         policy configurabile e suoi default
    rules.rs          regole di ispezione: sniffing, bombe, host, PDF
  parser/
    rewriter.rs       riscrittura HTML in streaming (lol_html)
    css.rs            sanitizzazione dei fogli di stile
    dom.rs            estrazione dei link
  engine/
    scheduler.rs      pool di worker e coda condivisa
    worker.rs         pipeline di elaborazione di un input
  report/             report JSON

corpus/             campioni benigni e maligni + ground truth
config/             policy di esempio
tests/              test di integrazione
scripts/            valutazione sperimentale
docs/               traccia e guida al testing
```

---

## Autori

| Studente| Matricola|
|---------|----------|
| Filippo Barboni | s352701 |
| Marika Fuccio | s354828 |
| Alessio Belluardo | s359092 |
