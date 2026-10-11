#!/usr/bin/env python3
"""
Build the technical report PDF from your own pqc_bench.py results.

Usage (after running pqc_bench.py on each device):
    pip install reportlab matplotlib
    python3 make_report.py --runs rpi4 laptop --names "Raspberry Pi 4" "Laptop (baseline)" \
        --author "Iqra Batool, Ph.D." --affil "University of New Brunswick" \
        --repo "https://github.com/<you>/pqc-constrained-bench" --out Batool_PQC_Constrained_Devices_Report.pdf

Each --runs entry is the --out prefix you gave pqc_bench.py (it reads <prefix>.csv and <prefix>_device.json).
List the most constrained device first and the baseline last; slowdowns are computed against the last one.
"""
import argparse, csv, json, math, os, tempfile
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak

PQ, CL = "#2a78d6", "#eb6834"
FRAME_PAYLOAD = 100   # usable bytes per IEEE 802.15.4 frame (127-byte PHY payload minus typical headers)
LORA_PAYLOAD = 51     # LoRaWAN maximum application payload at the slowest US915/EU868 data rates


def load(prefix):
    rows = list(csv.DictReader(open(prefix + ".csv")))
    dev = json.load(open(prefix + "_device.json"))
    for r in rows:
        r["median_us"] = float(r["median_us"]); r["p95_us"] = float(r["p95_us"]); r["sizes"] = json.loads(r["sizes"])
    return rows, dev


def wire_bytes(r):
    s = r["sizes"]
    if "ciphertext_B" in s: return s["public_key_B"] + s["ciphertext_B"]
    if r["algorithm"] == "X25519": return 2 * s["public_key_B"]
    return s["public_key_B"] + s.get("signature_B", s.get("signature_B_DER", 0))


def chart_times(runs, names, path):
    ops = [(r["algorithm"], r["operation"]) for r in runs[0][0]]
    n = len(runs)
    fig, ax = plt.subplots(figsize=(7.2, 0.26 * len(ops) + 1.2), dpi=200)
    h = 0.8 / n
    for k, (rows, _) in enumerate(runs):
        m = {(r["algorithm"], r["operation"]): r["median_us"] for r in rows}
        ys = [i + k * h for i in range(len(ops))]
        vals = [m.get(o, 0) for o in ops]
        cols = [(PQ if o[0].startswith("ML-") else CL) for o in ops]
        ax.barh(ys, vals, height=h * 0.92, color=cols, alpha=1 - 0.45 * k / max(1, n - 1), edgecolor="white", linewidth=0.6,
                label=names[k])
    ax.set_yticks([i + h * (n - 1) / 2 for i in range(len(ops))])
    ax.set_yticklabels([f"{a} {o}" for a, o in ops], fontsize=7)
    ax.invert_yaxis(); ax.set_xscale("log")
    ax.set_xlabel("Median time per operation (microseconds, log scale)", fontsize=8)
    ax.grid(axis="x", color="#e4e3de", linewidth=0.6); ax.set_axisbelow(True)
    for s in ["top", "right", "left"]: ax.spines[s].set_visible(False)
    if n > 1: ax.legend(fontsize=7, frameon=False, loc="lower right", title="darker = first device", title_fontsize=6.5)
    fig.tight_layout(); fig.savefig(path); plt.close(fig)


def chart_bytes(rows, path):
    order = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ECDSA-P256", "Ed25519"]
    first = {}
    for r in rows: first.setdefault(r["algorithm"], r)
    labs = [a for a in order if a in first]; vals = [wire_bytes(first[a]) for a in labs]
    fig, ax = plt.subplots(figsize=(7.2, 3.2), dpi=200)
    ax.barh(labs, vals, color=[PQ if a.startswith("ML-") else CL for a in labs], height=0.6, edgecolor="white")
    for i, v in enumerate(vals): ax.text(v + max(vals) * 0.01, i, f"{v:,} B", va="center", fontsize=7)
    ax.invert_yaxis(); ax.set_xlim(0, max(vals) * 1.18)
    ax.set_xlabel("Bytes exchanged (public key + ciphertext or signature)", fontsize=8)
    ax.tick_params(labelsize=7.5); ax.grid(axis="x", color="#e4e3de", linewidth=0.6); ax.set_axisbelow(True)
    for s in ["top", "right", "left"]: ax.spines[s].set_visible(False)
    fig.tight_layout(); fig.savefig(path); plt.close(fig)


def tbl(data, widths, header=True):
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    st = [("FONT", (0, 0), (-1, -1), "Helvetica", 7.6), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b8c2cf")),
          ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (1, 1), (-1, -1), "RIGHT")]
    if header: st += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9eef5")), ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 7.6)]
    t.setStyle(TableStyle(st)); return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--names", nargs="+", required=True)
    ap.add_argument("--author", default="Iqra Batool, Ph.D.")
    ap.add_argument("--affil", default="University of New Brunswick, Fredericton, Canada")
    ap.add_argument("--repo", default="[code and data repository URL]")
    ap.add_argument("--out", default="PQC_Constrained_Devices_Report.pdf")
    ap.add_argument("--watermark", default="")
    a = ap.parse_args()
    assert len(a.runs) == len(a.names), "give one --names entry per --runs entry"
    runs = [load(p) for p in a.runs]
    tmp = tempfile.mkdtemp()
    chart_times(runs, a.names, os.path.join(tmp, "t.png")); chart_bytes(runs[0][0], os.path.join(tmp, "b.png"))

    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontName="Times-Roman", fontSize=10, leading=13.5, spaceAfter=6)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold", fontSize=15, leading=19, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=11.5, spaceBefore=8, spaceAfter=4, textColor=colors.HexColor("#1d3557"))
    small = ParagraphStyle("s", parent=body, fontSize=8.5, leading=11, textColor=colors.HexColor("#444444"))
    S = []
    S += [Paragraph("Cost of NIST Post-Quantum Cryptography on Constrained Wireless Devices: Measurements of ML-KEM and ML-DSA Against Classical Baselines", h1),
          Paragraph(f"{a.author}<br/>{a.affil}<br/>Technical report, measurements taken {', '.join(d['timestamp_utc'][:10] for _, d in runs)}", small), Spacer(1, 8)]

    base_rows = runs[-1][0]; con_rows = runs[0][0]
    bm = {(r["algorithm"], r["operation"]): r["median_us"] for r in base_rows}
    ratios = [r["median_us"] / bm[(r["algorithm"], r["operation"])] for r in con_rows if bm.get((r["algorithm"], r["operation"]))]
    g = lambda alg, op, rows=con_rows: next(r["median_us"] for r in rows if r["algorithm"] == alg and r["operation"] == op)
    w = {r["algorithm"]: wire_bytes(r) for r in con_rows}
    abstract = (f"Federal policy now requires a transition to the NIST post-quantum standards ML-KEM (FIPS 203) and ML-DSA (FIPS 204). "
                f"This report measures their computation time and message sizes at all standardized parameter sets on {a.names[0]}"
                + (f", compared with {a.names[-1]}" if len(runs) > 1 else "") +
                f", against classical X25519, ECDSA P-256, and Ed25519. On {a.names[0]}, an ML-KEM-768 encapsulation took {g('ML-KEM-768','encaps'):.0f} microseconds "
                f"and an ML-DSA-65 signature took {g('ML-DSA-65','sign'):.0f} microseconds. Message size is the larger burden: one ML-KEM-768 exchange sends "
                f"{w['ML-KEM-768']:,} bytes versus {w['X25519']} for X25519, and an ML-DSA-65 public key plus signature is {w['ML-DSA-65']:,} bytes versus {w['Ed25519']} for Ed25519. "
                f"Code and raw data are available at {a.repo}.")
    S += [Paragraph("<b>Abstract.</b> " + abstract, body)]

    S += [Paragraph("1. Motivation", h2), Paragraph(
        "Executive Order 14412 (June 22, 2026) directs federal high-value systems to adopt post-quantum key establishment by December 31, 2030 and post-quantum signatures by December 31, 2031, "
        "and directs assistance to critical-infrastructure operators making the same transition. Constrained wireless devices, such as sensors, radios, and gateways with limited energy, memory, and airtime, "
        "are the hardest part of that migration. This report provides reproducible measurements as a first step toward an open benchmark and integration guide for such devices.", body)]

    S += [Paragraph("2. Setup", h2)]
    rows = [["Device", "Board / CPU", "Arch", "Cores", "RAM (MB)", "liboqs", "Python", "Runs per op"]]
    for (rws, d), nm in zip(runs, a.names):
        rows.append([nm, d.get("board_model", d.get("processor", "")) or "", d.get("machine", ""), str(d.get("cpu_count", "")),
                     str(d.get("ram_total_MB", "")), d.get("liboqs_version", ""), d.get("python", ""), rws[0]["runs"]])
    S += [tbl(rows, [1.2*inch, 1.6*inch, 0.6*inch, 0.45*inch, 0.6*inch, 0.6*inch, 0.6*inch, 0.65*inch]), Spacer(1, 4),
          Paragraph("Each operation was run the stated number of times after 20 warm-up runs; medians and 95th percentiles are reported. ML-KEM and ML-DSA use liboqs through liboqs-python; "
                    "classical algorithms use the Python cryptography library (OpenSSL). Signatures cover a 256-byte message, representative of a control message or firmware-manifest digest. "
                    "Timing includes Python call overhead, which affects classical and post-quantum operations alike.", body)]

    S += [Paragraph("3. Results", h2), Paragraph("Figure 1. Median time per operation on each device (log scale). Blue: post-quantum. Orange: classical.", small),
          Image(os.path.join(tmp, "t.png"), width=6.6*inch, height=6.6*inch * (0.26 * len(con_rows) + 1.2) / 7.2), PageBreak()]
    for (rws, d), nm in zip(runs, a.names):
        data = [["Algorithm", "Operation", "Median (us)", "p95 (us)"]] + [[r["algorithm"], r["operation"], f"{r['median_us']:.1f}", f"{r['p95_us']:.1f}"] for r in rws]
        S += [Paragraph(f"Table: timing on {nm}", small), tbl(data, [1.3*inch, 1.0*inch, 1.0*inch, 1.0*inch]), Spacer(1, 6)]
    if len(runs) > 1:
        S += [Paragraph(f"Across all operations, {a.names[0]} was {min(ratios):.1f} to {max(ratios):.1f} times slower than {a.names[-1]} "
                        f"(median slowdown {sorted(ratios)[len(ratios)//2]:.1f} times).", body)]
    S += [Paragraph("Figure 2. Bytes exchanged per key establishment or per signed message.", small), Image(os.path.join(tmp, "b.png"), width=6.6*inch, height=2.93*inch)]

    S += [Paragraph("4. What this means for wireless devices", h2)]
    imp = [["Exchange", "Bytes", f"802.15.4 frames (~{FRAME_PAYLOAD} B each)", f"LoRaWAN packets ({LORA_PAYLOAD} B max)"]]
    for alg in ["X25519", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "Ed25519", "ECDSA-P256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        if alg in w: imp.append([alg, f"{w[alg]:,}", str(math.ceil(w[alg] / FRAME_PAYLOAD)), str(math.ceil(w[alg] / LORA_PAYLOAD))])
    S += [tbl(imp, [1.3*inch, 0.9*inch, 1.9*inch, 1.9*inch]), Spacer(1, 4), Paragraph(
        "Frame counts are illustrative: they divide the bytes by a typical usable payload and ignore fragmentation headers, retransmissions, and certificate chains, all of which add more. "
        "Even so, they show the central problem: on low-power links, post-quantum protection multiplies the number of transmissions, and each transmission costs energy and airtime. "
        "On a fast processor computation is minor; on constrained links the bytes dominate. This is why device-specific measurement, gateway-side handling, and security-aware scheduling are needed.", body)]

    S += [Paragraph("5. Limitations", h2), Paragraph(
        "These are single-device microbenchmarks. They do not include radio transmission, energy measured at the device, end-to-end protocol handshakes, or microcontroller-class hardware, "
        "and Python call overhead inflates very short operations. Results describe algorithm cost, not FIPS 140 module validation.", body)]
    S += [Paragraph("6. Next steps", h2), Paragraph(
        "Next steps are measurements on microcontroller-class boards (for example with the pqm4 framework), energy measurement per operation, hybrid key exchange in a full protocol handshake, "
        "signed firmware updates over constrained links, and use of the measured costs in security-aware resource allocation.", body)]
    S += [Paragraph("Data availability", h2), Paragraph(f"Benchmark script, raw CSV results, and device descriptions: {a.repo}", body)]

    def deco(c, doc):
        c.saveState(); c.setFont("Helvetica", 7.5); c.setFillGray(0.4)
        c.drawRightString(letter[0] - 0.8*inch, 0.5*inch, f"{a.author}  |  page {doc.page}")
        if a.watermark:
            c.setFont("Helvetica-Bold", 20); c.setFillColorRGB(0.85, 0.1, 0.1, alpha=0.18)
            c.translate(letter[0] / 2, letter[1] / 2); c.rotate(35); c.drawCentredString(0, 0, a.watermark)
        c.restoreState()
    SimpleDocTemplate(a.out, pagesize=letter, leftMargin=0.85*inch, rightMargin=0.85*inch, topMargin=0.8*inch, bottomMargin=0.8*inch,
                      title="PQC on constrained wireless devices", author=a.author).build(S, onFirstPage=deco, onLaterPages=deco)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
