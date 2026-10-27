#!/usr/bin/env python3
"""Turns raw benchmark output into CSV, markdown tables and PNG charts.

    build/venv/bin/python bench/aggregate.py [RESULTS_DIR] [IMG_DIR]

Inputs (RESULTS_DIR, default build/bench-results):
    micro_cpp.json    Google Benchmark JSON (zkauth-microbench)
    micro_node.json   baseline-node/microbench.mjs output
    load/*.json       k6 summaries, <config>_<endpoint>_<vus>_<run>.json
Outputs:
    micro.csv, load.csv, tables.md   (RESULTS_DIR)
    *.png                            (IMG_DIR, default docs/img)
Load numbers are the median of the 3 runs of each cell.
"""
import csv
import glob
import json
import os
import re
import statistics
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402

RES = sys.argv[1] if len(sys.argv) > 1 else "build/bench-results"
IMG = sys.argv[2] if len(sys.argv) > 2 else "docs/img"
os.makedirs(IMG, exist_ok=True)

# Validated two-slot palette (dataviz reference, light surface): identity by
# hue (C++ blue, Node orange) and, redundantly, by line style / direct labels.
CPP, NODE = "#2a78d6", "#eb6834"
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": MUTED,
    "text.color": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.spines.top": False, "axes.spines.right": False, "font.size": 10,
    "axes.titlesize": 11, "axes.titleweight": "bold", "legend.frameon": False,
    "axes.axisbelow": True,  # gridlines stay behind the marks
})


def micro_rows():
    rows = []
    cpp = json.load(open(f"{RES}/micro_cpp.json"))
    for b in cpp["benchmarks"]:
        if b.get("aggregate_name") not in ("p50", "p99", "mean"):
            continue
        op = b["run_name"].split("/iterations")[0]
        rows.append(("C++", op, b["aggregate_name"], b["real_time"]))
    node = json.load(open(f"{RES}/micro_node.json"))
    for op, r in node.items():
        if isinstance(r, dict):
            for k in ("p50", "p99", "mean"):
                rows.append(("Node", op, k, r[f"{k}_us"]))
    table = {}
    for impl, op, k, v in rows:
        table.setdefault((impl, op), {})[k] = v
    out = [{"impl": i, "op": o, **{f"{k}_us": round(v[k], 1) for k in ("p50", "p99", "mean")}} for (i, o), v in table.items()]
    with open(f"{RES}/micro.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["impl", "op", "p50_us", "p99_us", "mean_us"])
        w.writeheader()
        w.writerows(out)
    return out, node.get("node", "")


def load_rows():
    cells = {}
    for path in glob.glob(f"{RES}/load/*_*_*_*.json"):
        m = re.match(r"(.+)_(verify-proof|verify-sig)_(\d+)_(\d)\.json$", os.path.basename(path))
        if not m:
            continue
        d = json.load(open(path))["metrics"]
        dur = d["http_req_duration"]["values"]
        cells.setdefault((m[1], m[2], int(m[3])), []).append({
            "rps": d["http_reqs"]["values"]["rate"], "p50": dur["med"], "p99": dur["p(99)"], "max": dur["max"],
            "ok": d["checks"]["values"]["rate"], "n": d["http_reqs"]["values"]["count"],
        })
    out = []
    for (cfg, ep, vus), runs in sorted(cells.items()):
        med = {k: statistics.median(r[k] for r in runs) for k in ("rps", "p50", "p99", "max")}
        out.append({"config": cfg, "endpoint": ep, "vus": vus, "runs": len(runs),
                    "rps": round(med["rps"], 1), "p50_ms": round(med["p50"], 3), "p99_ms": round(med["p99"], 3),
                    "max_ms": round(med["max"], 3), "correct": round(min(r["ok"] for r in runs), 6),
                    "requests": sum(r["n"] for r in runs)})
    with open(f"{RES}/load.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    return out


def place_end_labels(ax, labels, min_gap_px=12):
    """Direct labels at line ends, nudged vertically so they never overlap."""
    ax.figure.canvas.draw()
    to_px = ax.transData.transform
    items = sorted(((to_px((x, y))[1], x, y, t) for x, y, t in labels))
    placed = []
    for py, x, y, t in items:
        if placed and py - placed[-1] < min_gap_px:
            py = placed[-1] + min_gap_px
        placed.append(py)
        dy = py - to_px((x, y))[1]
        ax.annotate(t, (x, y), xytext=(7, dy), textcoords="offset points", va="center", fontsize=9, color=INK2)


def chart_micro(micro):
    pairs = [("Groth16 verify (one proof)", "groth16_verify/processed_vk", "groth16_verify/cached_curve"),
             ("Ethereum signature recovery", "ecrecover/reused_contexts", "ecrecover/ethers_verifyMessage")]
    get = {(r["impl"], r["op"]): r for r in micro}
    fig, axes = plt.subplots(1, 2, figsize=(9, 2.9))
    for ax, (title, cop, nop) in zip(axes, pairs):
        c, n = get.get(("C++", cop)), get.get(("Node", nop))
        if not c or not n:
            continue
        for row, (name, r, col) in enumerate([("C++ (libsnark / OpenSSL)", c, CPP), ("Node (snarkjs / ethers)", n, NODE)]):
            ax.barh(row, r["p50_us"], height=0.55, color=col)
            ax.annotate(f'{r["p50_us"]:,.0f} µs  (p99 {r["p99_us"]:,.0f})', (r["p50_us"], row), xytext=(6, 0),
                        textcoords="offset points", va="center", fontsize=9, color=INK2)
        ax.set_yticks([0, 1], ["C++", "Node"])
        ax.invert_yaxis()
        ax.set_title(title, loc="left")
        ax.set_xlabel("p50 latency per operation (µs) — lower is better")
        ax.set_xlim(0, max(c["p50_us"], n["p50_us"]) * 1.6)
        ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(f"{IMG}/micro_latency.png", dpi=150)
    plt.close(fig)


def chart_load(load, metric, ylabel, fname, better, log=False):
    fig, axes = plt.subplots(1, 2, figsize=(9.5, 3.4))
    titles = {"verify-proof": "POST /verify-proof", "verify-sig": "POST /verify-sig"}
    for ax, ep in zip(axes, ("verify-proof", "verify-sig")):
        ends = []
        for cfg in sorted({r["config"] for r in load}):
            pts = sorted((r["vus"], r[metric]) for r in load if r["config"] == cfg and r["endpoint"] == ep)
            if not pts:
                continue
            impl = "C++" if cfg.startswith("cpp") else "Node"
            multi = not cfg.endswith("-1")
            xs = [[1, 8, 64].index(v) for v, _ in pts]  # categorical positions
            ax.plot(xs, [y for _, y in pts], color=CPP if impl == "C++" else NODE, linewidth=2,
                    linestyle="-" if multi else (0, (4, 2)), marker="o" if multi else "s", markersize=6,
                    markeredgecolor=SURFACE, markeredgewidth=1.5,
                    label=f'{impl}, {"12 threads" if impl == "C++" and multi else "cluster ×12" if multi else "1 thread" if impl == "C++" else "1 process"}')
            ends.append((xs[-1], pts[-1][1], f"{pts[-1][1]:,.0f}" if metric == "rps" or pts[-1][1] >= 100 else f"{pts[-1][1]:,.1f}"))
        ax.set_title(titles[ep], loc="left")
        ax.set_xticks([0, 1, 2], ["1", "8", "64"])
        ax.set_xlabel("concurrent connections (k6 virtual users)")
        ax.set_ylabel(ylabel)
        if log:
            ax.set_yscale("log")
            ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
        else:
            ax.set_ylim(bottom=0)
        ax.grid(axis="x", visible=False)
        ax.margins(x=0.08)
        place_end_labels(ax, ends)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=4, fontsize=9, bbox_to_anchor=(0.5, 1.02))
    fig.text(0.99, 0.01, better, ha="right", fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.02, 1, 0.92))
    fig.savefig(f"{IMG}/{fname}", dpi=150)
    plt.close(fig)


def chart_optimisations(micro, extra):
    get = {(r["impl"], r["op"]): r["p50_us"] for r in micro}
    items = [("Groth16 verify,\nprocessed vk", get.get(("C++", "groth16_verify/unprocessed_vk")), get.get(("C++", "groth16_verify/processed_vk")), "µs"),
             ("ecrecover, reused\nOpenSSL contexts", get.get(("C++", "ecrecover/fresh_contexts")), get.get(("C++", "ecrecover/reused_contexts")), "µs")]
    items += extra
    items = [i for i in items if i[1] and i[2]]
    fig, axes = plt.subplots(1, len(items), figsize=(3.2 * len(items), 3.1))
    for ax, (name, before, after, unit) in zip(axes, items):
        ax.bar([0, 1], [before, after], width=0.55, color=[MUTED, CPP])
        for x, v in ((0, before), (1, after)):
            ax.annotate(f"{v:,.1f} {unit}" if v < 100 else f"{v:,.0f} {unit}", (x, v), xytext=(0, 3),
                        textcoords="offset points", ha="center", fontsize=9, color=INK2)
        ax.set_xticks([0, 1], ["before", "after"])
        ratio = before / after
        ax.set_title(f"{name}\n{ratio:.2f}× faster" if ratio < 1.5 else f"{name}\n{ratio:.1f}× faster", loc="left", fontsize=9.5)
        ax.set_ylim(0, before * 1.2)
        ax.grid(axis="x", visible=False)
    fig.tight_layout()
    fig.savefig(f"{IMG}/optimisations.png", dpi=150)
    plt.close(fig)


def tables(micro, load, node_version):
    lines = ["### Micro-benchmarks (per operation, µs)", "", "| Implementation | Operation | p50 | p99 | mean |", "|---|---|---:|---:|---:|"]
    for r in sorted(micro, key=lambda r: (r["op"].split("/")[0], r["impl"])):
        lines.append(f'| {r["impl"]} | `{r["op"]}` | {r["p50_us"]:,.1f} | {r["p99_us"]:,.1f} | {r["mean_us"]:,.1f} |')
    for ep in ("verify-proof", "verify-sig"):
        lines += ["", f"### Load: POST /{ep} (median of 3 × 10 s runs)", "",
                  "| Config | VUs | req/s | p50 ms | p99 ms | max ms | correct verdicts | requests |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for r in sorted((r for r in load if r["endpoint"] == ep), key=lambda r: (r["config"], r["vus"])):
            lines.append(f'| {r["config"]} | {r["vus"]} | {r["rps"]:,.0f} | {r["p50_ms"]:.2f} | {r["p99_ms"]:.2f} | '
                         f'{r["max_ms"]:.1f} | {100 * r["correct"]:.2f}% | {r["requests"]:,} |')
    open(f"{RES}/tables.md", "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    micro, node_version = micro_rows()
    load = load_rows() if glob.glob(f"{RES}/load/*.json") else []
    chart_micro(micro)
    extra = []
    if os.path.exists(f"{RES}/extra_optimisations.json"):
        extra = [tuple(x) for x in json.load(open(f"{RES}/extra_optimisations.json"))]
    chart_optimisations(micro, extra)
    if load:
        chart_load(load, "rps", "requests per second", "load_throughput.png", "higher is better")
        chart_load(load, "p99_ms", "p99 latency (ms, log scale)", "load_p99.png", "lower is better", log=True)
    tables(micro, load, node_version)
    print(open(f"{RES}/tables.md").read())
