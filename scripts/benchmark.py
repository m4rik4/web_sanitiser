from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import threading
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import psutil

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
CORPUS = ROOT / "corpus"
POLICY = ROOT / "config" / "default_policy.json"
FIGURES = SCRIPTS / "figures"
SYNTH = SCRIPTS / ".synthetic"      # input generati, usa-e-getta
SCRATCH = SCRIPTS / ".scratch"      # output ripuliti e report usa-e-getta

TAGLIE_KB = [16, 64, 256, 1024, 4096]
BATCH_N, BATCH_KB = 120, 64

# rotte di evil-origin per il confronto con e senza fetch delle sotto-risorse
ROTTE_FETCH = ["/html/resource-count-bomb", "/html/recursive-include"]

BLU, ARANCIO, VERDE, GRIGIO = "#2a78d6", "#eb6834", "#1baf7a", "#898781"

# esecuzione della cli e cronometro

def trova_binario(esplicito=None) -> Path:
    if esplicito:
        return Path(esplicito).resolve()
    nome = "web-sanitiser.exe" if os.name == "nt" else "web-sanitiser"
    p = ROOT / "target" / "release" / nome
    if not p.exists():
        raise SystemExit(f"{p} non esiste: compila con  cargo build --release")
    return p


def esegui(binario: Path, inputs, threads=1, config=POLICY, memoria=False, report=False):
    out_dir, rep_path = SCRATCH / "out", SCRATCH / "report.json"
    shutil.rmtree(out_dir, ignore_errors=True)
    cmd = [str(binario)]
    for i in inputs:
        cmd += ["-i", str(i)]
    cmd += ["-t", str(threads), "-c", str(config), "-o", str(out_dir), "-r", str(rep_path)]

    picco = None
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    if memoria:
        def campiona():
            nonlocal picco
            try:
                p = psutil.Process(proc.pid)
                while proc.poll() is None:
                    rss = p.memory_info().rss
                    picco = rss if picco is None else max(picco, rss)
                    time.sleep(0.003)
            except psutil.Error:
                pass
        t = threading.Thread(target=campiona, daemon=True)
        t.start()
        proc.wait()
        t.join(timeout=1)
    else:
        proc.wait()
    tempo = time.perf_counter() - t0

    # 0 vuol dire tutto sanitizzato e 1 almeno un rifiuto, qualunque altro codice è un'esecuzione fallita 
    if proc.returncode not in (0, 1):
        raise SystemExit(f"la cli è uscita con codice {proc.returncode}: {' '.join(cmd)}")
    dati = json.loads(rep_path.read_text(encoding="utf-8")) if report and rep_path.exists() else None
    return tempo, picco, dati


def cronometra(fn, reps: int) -> float:
    fn()
    return statistics.median(fn() for _ in range(reps))


def policy_loopback(fetch: bool) -> Path:
    p = json.loads(POLICY.read_text(encoding="utf-8"))
    # stessi valori che tests/evil_origin_test.rs usa sugli scenari che attivano il crawl
    p.update({"allow_loopback": True, "fetch_host_allowlist": ["localhost", "127.0.0.1"],
              "fetch_subresources": fetch, "max_fetch_depth": 2,
              "max_total_fetch_bytes": 100 * 1024 * 1024})
    path = SCRATCH / f"policy_fetch_{fetch}.json"
    path.write_text(json.dumps(p, indent=2), encoding="utf-8")
    return path


def leggibile(n) -> str:
    if n is None:
        return "n/d"
    v = float(n)
    for u in ("B", "KiB", "MiB", "GiB"):
        if v < 1024 or u == "GiB":
            return f"{v:.1f} {u}"
        v /= 1024

# corpus sintetico
# il corpus di `corpus/` serve alla correttezza: casi scelti a mano, piccoli e tutti diversi
# per latenza e throughput servono invece input della stessa natura ma di dimensione crescente
# qui le pagine sono la ripetizione dello stesso blocco

BLOCCO = """<p>testo di riempimento numero {n}, con un <a href="https://example.org/{n}">link lecito</a>.</p>
<div onclick="alert({n})">handler inline da rimuovere</div>
<script>var x{n} = {n};</script>
<a href="javascript:void({n})">schema pericoloso</a>
<iframe src="https://evil.example/{n}"></iframe>
<p>altro testo, cosi' il rapporto fra markup innocuo e costrutti da neutralizzare
resta lo stesso a ogni dimensione e le curve sono confrontabili fra loro.</p>
"""


def genera_pagina(path: Path, byte_voluti: int) -> int:
    testa = '<!doctype html>\n<html lang="it">\n<head><meta charset="utf-8">\n<title>bench</title></head>\n<body>\n'
    pezzi, lung, n = [testa], len(testa), 0
    while lung < byte_voluti:
        n += 1
        b = BLOCCO.format(n=n)
        pezzi.append(b)
        lung += len(b)
    pezzi.append("</body>\n</html>\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("".join(pezzi))
    return path.stat().st_size


def genera_corpus(taglie, batch_n, batch_kb) -> dict:
    print("[corpus] genero gli input sintetici")
    scaling = []
    for kb in taglie:
        p = SYNTH / f"size_{kb:05d}KiB.html"
        scaling.append({"kb": kb, "path": str(p), "bytes": genera_pagina(p, kb * 1024)})
    batch = SYNTH / "batch"
    shutil.rmtree(batch, ignore_errors=True)
    totale = sum(genera_pagina(batch / f"p{i:04d}.html", batch_kb * 1024)
                 for i in range(batch_n))
    print(f"         {len(taglie)} taglie + batch di {batch_n} file ({leggibile(totale)})")
    return {"scaling": scaling, "batch": {"path": str(batch), "count": batch_n,
                                          "bytes": totale}}

# 1. correttezza

def misura_correttezza(binario) -> dict:
    gt = json.loads((CORPUS / "ground_truth.json").read_text(encoding="utf-8"))
    righe = []
    print(f"[correttezza] {len(gt['entries'])} campioni")
    for voce in gt["entries"]:
        _, _, rep = esegui(binario, [CORPUS / voce["path"]], report=True)
        job = rep["jobs"][0]
        regole = [a["rule"] for a in job["actions"]]
        mancanti = [r for r in voce.get("expected_rules", []) if r not in regole]
        riga = {"campione": voce["path"], "label": voce["label"], "status": job["status"],
                "atteso": voce["expected_status"], "azioni": len(regole), "regole": regole,
                "mancanti": mancanti,
                "toccato": job["status"] == "refused" or bool(regole),
                "conforme": job["status"] == voce["expected_status"] and not mancanti}
        righe.append(riga)
        print(f"  {'ok  ' if riga['conforme'] else 'DIFF'} {voce['path']:<42} "
              f"{job['status']:<10} {len(regole):>3} azioni")

    tp = sum(1 for r in righe if r["label"] == "malicious" and r["toccato"])
    fn = sum(1 for r in righe if r["label"] == "malicious" and not r["toccato"])
    fp = sum(1 for r in righe if r["label"] == "benign" and r["toccato"])
    tn = sum(1 for r in righe if r["label"] == "benign" and not r["toccato"])
    ris = {"righe": righe, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
           "detection_rate": tp / (tp + fn) if tp + fn else None,
           "false_positive_rate": fp / (fp + tn) if fp + tn else None,
           "conformi": sum(1 for r in righe if r["conforme"]), "totale": len(righe),
           "non_conformi": [r["campione"] for r in righe if not r["conforme"]]}
    print(f"  -> detection rate {ris['detection_rate']:.1%}, falsi positivi "
          f"{ris['false_positive_rate']:.1%}, conformi {ris['conformi']}/{ris['totale']}")
    return ris

# 2. prestazioni

def misura_prestazioni(binario, corpus, reps, origin) -> dict:
    """latenza per dimensione, throughput, e il costo del fetch"""
    print("[prestazioni] latenza in funzione della dimensione (1 thread)")
    latenze = []
    for voce in corpus["scaling"]:
        # si misura un lotto di copie e si divide
        n = max(2, min(64, (8 * 1024 * 1024) // voce["bytes"]))
        d = SCRATCH / f"lat_{voce['kb']}"
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)
        for i in range(n):
            shutil.copy2(voce["path"], d / f"{i:03d}.html")
        t = cronometra(lambda: esegui(binario, [d])[0], reps)
        latenze.append({"bytes": voce["bytes"], "copie": n, "tempo_lotto_s": t,
                        "latenza_s": t / n, "mib_s": voce["bytes"] / (t / n) / 1024**2})
        print(f"  {leggibile(voce['bytes']):>10}: {t/n*1000:8.3f} ms/input "
              f"({latenze[-1]['mib_s']:6.1f} MiB/s)")

    core = os.cpu_count() or 1
    batch, n_file, tot = Path(corpus["batch"]["path"]), corpus["batch"]["count"], corpus["batch"]["bytes"]
    print(f"[prestazioni] throughput sul batch di {n_file} input")
    throughput = []
    for th in sorted({1, max(1, core // 2), core}):
        t = cronometra(lambda: esegui(binario, [batch], threads=th)[0], reps)
        throughput.append({"threads": th, "tempo_s": t, "input_s": n_file / t,
                           "mib_s": tot / t / 1024**2})
        print(f"  {th:>2} thread: {t:6.3f} s -> {n_file/t:7.1f} input/s, {tot/t/1024**2:6.1f} MiB/s")

    fetch = None
    if origin:
        print(f"[prestazioni] con e senza fetch delle sotto-risorse ({origin})")
        senza, con = policy_loopback(False), policy_loopback(True)
        fetch = []
        for rotta in ROTTE_FETCH:
            url = origin.rstrip("/") + rotta
            ultimo = {}

            def con_fetch():
                t, _, rep = esegui(binario, [url], config=con, report=True)
                ultimo["report"] = rep
                return t

            try:
                a = cronometra(lambda: esegui(binario, [url], config=senza)[0], max(3, reps // 2))
                b = cronometra(con_fetch, max(3, reps // 2))
            except Exception as e:
                print(f"  SALTATA {rotta}: {e}")
                continue

            # quante sotto-risorse il crawler ha davvero toccato
            azioni = [x.get("rule", "") for x in
                      (ultimo.get("report") or {}).get("jobs", [{}])[0].get("actions", [])]
            # `fetch-subresource` sono le richieste andate a buon fine
            n_sub = sum(1 for r in azioni if r == "fetch-subresource")
            n_altre = sum(1 for r in azioni if r.startswith(
                ("subresource-", "reject-subresource", "reject-active-subresource",
                 "block-ssrf-subresource")))
            fetch.append({"rotta": rotta, "senza_s": a, "con_s": b, "delta_s": b - a,
                          "sotto_risorse": n_sub, "altre_azioni_crawl": n_altre})
            print(f"  {rotta:<28} senza {a*1000:7.1f} ms | con {b*1000:8.1f} ms | "
                  f"{(b-a)*1000:+7.1f} ms | {n_sub} sotto-risorse"
                  + (f" (+{n_altre} budget/errori)" if n_altre else ""))
            if n_sub == 0 and n_altre == 0:
                print("      ATTENZIONE: nessuna sotto-risorsa scaricata. La rotta non esiste nel\n"
                      "      container, oppure i suoi riferimenti sono stati rimossi dalla\n"
                      "      sanitizzazione prima del crawl: cosi' il confronto non misura il download.")

    return {"latenza": latenze, "throughput": throughput, "fetch": fetch}

# 3. scalabilità

def misura_scalabilita(binario, corpus, reps) -> dict:
    batch = Path(corpus["batch"]["path"])
    core = os.cpu_count() or 1
    gradi = sorted({t for t in range(1, core + 1) if t <= 8 or t % 2 == 0 or t == core})
    print(f"[scalabilita'] {corpus['batch']['count']} input, {core} core, gradi {gradi}")
    punti, base = [], None
    for th in gradi:
        t = cronometra(lambda: esegui(binario, [batch], threads=th)[0], reps)
        base = t if th == 1 else base
        punti.append({"threads": th, "tempo_s": t, "speedup": base / t,
                      "efficienza": base / t / th})
        print(f"  t={th:>3}: {t:6.3f} s  speedup {base/t:5.2f}x  efficienza {base/t/th:5.1%}")
    migliore = max(punti, key=lambda p: p["speedup"])
    print(f"  -> speed-up massimo {migliore['speedup']:.2f}x con {migliore['threads']} thread")
    return {"punti": punti, "core": core}

# 4. memoria

def misura_memoria(binario, corpus, reps) -> dict:
    print("[memoria] picco su un solo input, taglie crescenti")
    per_taglia = []
    for voce in corpus["scaling"]:
        picchi = [esegui(binario, [voce["path"]], memoria=True)[1] for _ in range(reps)]
        picchi = [p for p in picchi if p]
        med = statistics.median(picchi) if picchi else None
        per_taglia.append({"bytes": voce["bytes"], "picco_bytes": med})
        print(f"  {leggibile(voce['bytes']):>10} input -> picco {leggibile(med):>10}")

    batch = Path(corpus["batch"]["path"])
    core = os.cpu_count() or 1
    print("[memoria] picco sul batch al variare dei thread")
    per_thread = []
    for th in sorted({1, 2, max(1, core // 2), core}):
        picchi = [esegui(binario, [batch], threads=th, memoria=True)[1] for _ in range(reps)]
        picchi = [p for p in picchi if p]
        med = statistics.median(picchi) if picchi else None
        per_thread.append({"threads": th, "picco_bytes": med})
        print(f"  t={th:>3} -> picco {leggibile(med):>10}")
    return {"per_taglia": per_taglia, "per_thread": per_thread}

# grafici

def _stile():
    plt.rcParams.update({"font.size": 9, "axes.titlesize": 10, "axes.titleweight": "bold",
                         "axes.spines.top": False, "axes.spines.right": False,
                         "grid.color": "#e1e0d9", "grid.linewidth": 0.7,
                         "legend.frameon": False, "lines.linewidth": 2, "lines.markersize": 6})


def _griglia(ax, asse="y"):
    ax.grid(True, axis=asse)
    ax.set_axisbelow(True)


def _byte(x, _=None):
    return f"{x/1024**2:.0f} MiB" if x >= 1024**2 else f"{x/1024:.0f} KiB"


def _salva(fig, nome):
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / f"{nome}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"[figura] scripts/figures/{nome}.png")


def figura_correttezza(d):
    fig, ax = plt.subplots(figsize=(5.5, 3.6))
    valori = [(d["detection_rate"] or 0) * 100, (d["false_positive_rate"] or 0) * 100]
    conteggi = [f"{d['tp']}/{d['tp']+d['fn']}", f"{d['fp']}/{d['fp']+d['tn']}"]
    barre = ax.bar(["Detection rate\n(maligni)", "Falsi positivi\n(benigni)"], valori,
                   color=[VERDE, ARANCIO], width=0.5, zorder=3)
    for b, v, c in zip(barre, valori, conteggi):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.1f}%  ({c})", ha="center",
                fontsize=9, fontweight="bold")
    ax.set_ylim(0, 112)
    ax.set_ylabel("percentuale dei campioni")
    ax.set_title("Correttezza sul corpus etichettato")
    _griglia(ax)
    fig.text(0.5, -0.04, f"TP {d['tp']} · FN {d['fn']} · FP {d['fp']} · TN {d['tn']}  ·  "
                         f"conformi alla ground truth {d['conformi']}/{d['totale']}",
             ha="center", fontsize=8, color="#52514e")
    _salva(fig, "fig1_correttezza")


def figura_prestazioni(d):
    lat, thr = d["latenza"], d["throughput"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.5, 3.8))
    xs = [p["bytes"] for p in lat]
    ys = [p["latenza_s"] * 1000 for p in lat]
    a1.plot(xs, ys, color=BLU, marker="o", label="misurata", zorder=3)
    k = ys[0] / xs[0]
    a1.plot(xs, [k * x for x in xs], "--", color=GRIGIO, linewidth=1.4,
            label="crescita lineare")
    a1.set_xscale("log", base=2); a1.set_yscale("log")
    a1.xaxis.set_major_formatter(FuncFormatter(_byte))
    a1.set_xlabel("dimensione dell'input"); a1.set_ylabel("latenza per input (ms)")
    a1.set_title("Latenza in funzione della dimensione"); a1.legend(loc="upper left")
    _griglia(a1, "both")

    et = [f"{p['threads']}" for p in thr]
    v = [p["input_s"] for p in thr]
    barre = a2.bar(et, v, color=VERDE, width=0.5, zorder=3)
    for b, x in zip(barre, v):
        a2.text(b.get_x() + b.get_width() / 2, x * 1.02, f"{x:.0f}", ha="center",
                fontsize=9, fontweight="bold")
    a2.set_ylim(0, max(v) * 1.2)
    a2.set_xlabel("thread worker (-t)"); a2.set_ylabel("input al secondo")
    a2.set_title("Throughput sul batch")
    _griglia(a2)
    _salva(fig, "fig2_prestazioni")


def figura_scalabilita(d):
    p = d["punti"]
    t = [x["threads"] for x in p]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.5, 3.8))
    a1.plot(t, t, "--", color=GRIGIO, linewidth=1.4, label="ideale")
    a1.plot(t, [x["speedup"] for x in p], color=BLU, marker="o", label="misurato", zorder=3)
    a1.set_xticks(t); a1.set_xlabel("thread worker (-t)")
    a1.set_ylabel("speed-up rispetto a 1 thread")
    a1.set_title("Curva di speed-up"); a1.legend(loc="upper left")
    _griglia(a1, "both")

    a2.plot(t, [x["efficienza"] * 100 for x in p], color=ARANCIO, marker="o", zorder=3)
    a2.set_xticks(t); a2.set_ylim(0, 108)
    a2.set_xlabel("thread worker (-t)"); a2.set_ylabel("efficienza (%)")
    a2.set_title("Efficienza = speed-up / thread")
    _griglia(a2)
    _salva(fig, "fig3_scalabilita")


def figura_memoria(d):
    ta, th = d["per_taglia"], d["per_thread"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.5, 3.8))
    xs = [p["bytes"] for p in ta if p["picco_bytes"]]
    ys = [p["picco_bytes"] / 1024**2 for p in ta if p["picco_bytes"]]
    a1.plot(xs, ys, color=BLU, marker="o", zorder=3)
    a1.set_xscale("log", base=2); a1.set_ylim(0, max(ys) * 1.25 if ys else 1)
    a1.xaxis.set_major_formatter(FuncFormatter(_byte))
    a1.set_xlabel("dimensione dell'input"); a1.set_ylabel("picco di memoria (MiB)")
    a1.set_title("Memoria in funzione dell'input (1 thread)")
    _griglia(a1)

    et = [str(p["threads"]) for p in th if p["picco_bytes"]]
    v = [p["picco_bytes"] / 1024**2 for p in th if p["picco_bytes"]]
    barre = a2.bar(et, v, color=VERDE, width=0.5, zorder=3)
    for b, x in zip(barre, v):
        a2.text(b.get_x() + b.get_width() / 2, x * 1.02, f"{x:.0f}", ha="center",
                fontsize=9, fontweight="bold")
    a2.set_ylim(0, max(v) * 1.2 if v else 1)
    a2.set_xlabel("thread worker (-t)"); a2.set_ylabel("picco di memoria (MiB)")
    a2.set_title("Memoria in funzione dei worker (batch)")
    _griglia(a2)
    _salva(fig, "fig4_memoria")


def figura_fetch(righe):
    r = sorted(righe, key=lambda x: x["con_s"])
    y = range(len(r))
    fig, ax = plt.subplots(figsize=(8, 0.5 * len(r) + 2))
    ax.barh([i + 0.2 for i in y], [x["senza_s"] * 1000 for x in r], height=0.38,
            color=BLU, label="senza fetch", zorder=3)
    ax.barh([i - 0.2 for i in y], [x["con_s"] * 1000 for x in r], height=0.38,
            color=ARANCIO, label="con fetch", zorder=3)
    ax.set_yticks(list(y), [x["rotta"] for x in r], fontsize=8)
    ax.set_xlabel("tempo di parete per input (ms), avvio del processo incluso in entrambe")
    ax.set_title("Costo del fetch delle sotto-risorse")
    ax.legend(loc="lower right")
    _griglia(ax, "x")
    _salva(fig, "fig5_sottorisorse")

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=None, help="percorso del binario (default target/release)")
    ap.add_argument("--reps", type=int, default=5, help="ripetizioni per punto (default 5)")
    ap.add_argument("--origin", default=None, help="base url di evil-origin, es. http://localhost:3100")
    ap.add_argument("--only", choices=["correttezza", "prestazioni", "scalabilita", "memoria"],
                    default=None, help="esegui una misura sola")
    ap.add_argument("--quick", action="store_true", help="corpus piccolo, 2 ripetizioni: prova della catena")
    args = ap.parse_args()

    binario = trova_binario(args.bin)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    SYNTH.mkdir(parents=True, exist_ok=True)
    taglie, batch_n, reps = TAGLIE_KB, BATCH_N, args.reps
    if args.quick:
        taglie, batch_n, reps = [16, 64, 256], 24, 2

    misure = [args.only] if args.only else ["correttezza", "prestazioni", "scalabilita", "memoria"]
    servono_input = any(m in misure for m in ("prestazioni", "scalabilita", "memoria"))
    corpus = genera_corpus(taglie, batch_n, BATCH_KB) if servono_input else None

    ris = {}
    if (SCRIPTS / "results.json").exists():        # così non si perdono le misure già prese
        ris = json.loads((SCRIPTS / "results.json").read_text(encoding="utf-8"))
    ris["ambiente"] = {"data": time.strftime("%Y-%m-%d %H:%M"), "core": os.cpu_count(),
                       "reps": reps, "binario": str(binario)}

    _stile()
    if "correttezza" in misure:
        ris["correttezza"] = misura_correttezza(binario)
        figura_correttezza(ris["correttezza"])
    if "prestazioni" in misure:
        ris["prestazioni"] = misura_prestazioni(binario, corpus, reps, args.origin)
        figura_prestazioni(ris["prestazioni"])
        if ris["prestazioni"]["fetch"]:
            figura_fetch(ris["prestazioni"]["fetch"])
    if "scalabilita" in misure:
        ris["scalabilita"] = misura_scalabilita(binario, corpus, reps)
        figura_scalabilita(ris["scalabilita"])
    if "memoria" in misure:
        ris["memoria"] = misura_memoria(binario, corpus, reps)
        figura_memoria(ris["memoria"])

    (SCRIPTS / "results.json").write_text(json.dumps(ris, indent=2, ensure_ascii=False),
                                          encoding="utf-8")
    print(f"\n[bench] dati in scripts/results.json, figure in scripts/figures/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
