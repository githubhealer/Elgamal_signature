import math
import random
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from elgamal_core import generate_keys, verify
from elgamal_tests import (
    run_before_fix, run_after_fix,
    run_timing_benchmark, run_overhead_benchmark,
)

BG      = "#0f1117"
PANEL   = "#1a1d27"
ACCENT  = "#6c63ff"
TEXT    = "#e0e0e0"
DIM     = "#6b7280"
RED_CLR = "#ff4d4d"
ORG_CLR = "#ff9500"
GRN_CLR = "#2ecc71"
GOLD    = "#f0c040"


def _append(log_widget, text, colour=TEXT):
    log_widget.configure(state="normal")
    tag = f"col_{colour.replace('#', '')}"
    log_widget.tag_configure(tag, foreground=colour)
    log_widget.insert(tk.END, text + "\n", tag)
    log_widget.see(tk.END)
    log_widget.configure(state="disabled")

def _clear(log_widget):
    log_widget.configure(state="normal")
    log_widget.delete("1.0", tk.END)
    log_widget.configure(state="disabled")


class ElGamalApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("ElGamal Digital Signature Demo - Educational Cryptography")
        self.configure(bg=BG)
        self.state("zoomed")

        self.keys        = None
        self.before_data = None
        self.after_data  = None
        self.bench_data  = None
        self.overhead    = (None, None)

        self._build_ui()

    def _build_ui(self):
        banner = tk.Frame(self, bg=ACCENT, height=52)
        banner.pack(fill="x")
        tk.Label(
            banner, text="ElGamal Digital Signature - Security Demo",
            font=("Segoe UI", 16, "bold"), bg=ACCENT, fg="white",
        ).pack(side="left", padx=20, pady=10)
        tk.Label(
            banner, text="25WSC1BRS09's Cryptography and Network Security",
            font=("Segoe UI", 10), bg=ACCENT, fg="#d0cfff",
        ).pack(side="right", padx=20)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=8)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_left_panel(body)
        self._build_log(body)
        self._build_graphs(body)

    def _build_left_panel(self, parent):
        panel = tk.Frame(parent, bg=PANEL, width=220, bd=0)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        panel.pack_propagate(False)

        tk.Label(panel, text="Controls", font=("Segoe UI", 13, "bold"),
                 bg=PANEL, fg=ACCENT).pack(pady=(18, 8))

        btn_cfg = dict(font=("Segoe UI", 10, "bold"), bd=0, cursor="hand2",
                       relief="flat", pady=9, padx=6)

        self.btn_gen = tk.Button(
            panel, text="Generate Keys", bg=ACCENT, fg="white",
            activebackground="#5752d1", command=self._gen_keys, **btn_cfg)
        self.btn_gen.pack(fill="x", padx=14, pady=6)

        self.btn_attack = tk.Button(
            panel, text="Run Attack (Bad k)", bg="#c0392b", fg="white",
            activebackground="#922b21", command=self._run_attack,
            state="disabled", **btn_cfg)
        self.btn_attack.pack(fill="x", padx=14, pady=6)

        self.btn_fix = tk.Button(
            panel, text="Apply Prevention", bg="#1a7a4a", fg="white",
            activebackground="#145c38", command=self._run_fix,
            state="disabled", **btn_cfg)
        self.btn_fix.pack(fill="x", padx=14, pady=6)

        self.btn_graph = tk.Button(
            panel, text="Show Graphs", bg="#7c6200", fg="white",
            activebackground="#594700", command=self._show_graphs,
            state="disabled", **btn_cfg)
        self.btn_graph.pack(fill="x", padx=14, pady=6)

        ttk.Separator(panel, orient="horizontal").pack(fill="x", padx=10, pady=14)

        tk.Label(panel, text="Summary Stats", font=("Segoe UI", 11, "bold"),
                 bg=PANEL, fg=GOLD).pack()

        self.stat_vars = {}
        for key, label in [
            ("broken_before", "Broken (before)"),
            ("forged_before", "Forged (before)"),
            ("secure_before", "Secure (before)"),
            ("broken_after",  "Broken (after)"),
            ("forged_after",  "Forged (after)"),
            ("secure_after",  "Secure (after)"),
        ]:
            row = tk.Frame(panel, bg=PANEL)
            row.pack(fill="x", padx=14, pady=2)
            tk.Label(row, text=label, font=("Segoe UI", 9),
                     bg=PANEL, fg=TEXT, anchor="w").pack(side="left")
            var = tk.StringVar(value="-")
            self.stat_vars[key] = var
            tk.Label(row, textvariable=var, font=("Segoe UI", 9, "bold"),
                     bg=PANEL, fg=GOLD, anchor="e").pack(side="right")

        ttk.Separator(panel, orient="horizontal").pack(fill="x", padx=10, pady=14)
        self.key_info = tk.Text(
            panel, height=8, bg="#12151f", fg=DIM,
            font=("Consolas", 8), bd=0, state="disabled", wrap="word",
            padx=6, pady=6)
        self.key_info.pack(fill="x", padx=10, pady=(0, 10))

    def _build_log(self, parent):
        frame = tk.Frame(parent, bg=BG)
        frame.grid(row=0, column=1, sticky="nsew")
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        tk.Label(frame, text="Signature Log", font=("Segoe UI", 12, "bold"),
                 bg=BG, fg=TEXT).grid(row=0, column=0, sticky="w", pady=(4, 4))

        self.log = scrolledtext.ScrolledText(
            frame, bg="#0a0c14", fg=TEXT, font=("Consolas", 9),
            bd=0, highlightthickness=0, state="disabled", wrap="word")
        self.log.grid(row=1, column=0, sticky="nsew")

        leg = tk.Frame(frame, bg=BG)
        leg.grid(row=2, column=0, sticky="w", pady=4)
        for colour, label in [
            (RED_CLR, "RED = BROKEN (bad k)"),
            (ORG_CLR, "ORANGE = FORGED (reused k)"),
            (GRN_CLR, "GREEN = SECURE (fresh k)"),
        ]:
            tk.Label(leg, text="*", fg=colour, bg=BG,
                     font=("Segoe UI", 13)).pack(side="left")
            tk.Label(leg, text=label + "   ", fg=DIM, bg=BG,
                     font=("Segoe UI", 9)).pack(side="left")

    def _build_graphs(self, parent):
        outer = tk.Frame(parent, bg=PANEL, width=520)
        outer.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        outer.pack_propagate(False)
        parent.columnconfigure(2, weight=0)

        tk.Label(outer, text="Analytics", font=("Segoe UI", 12, "bold"),
                 bg=PANEL, fg=TEXT).pack(pady=(8, 4))

        self.fig = Figure(figsize=(5.1, 8), dpi=95, facecolor=PANEL)
        self.fig.subplots_adjust(hspace=0.55, left=0.13, right=0.97,
                                 top=0.95, bottom=0.06)

        self.axes = [self.fig.add_subplot(4, 1, i) for i in range(1, 5)]
        for ax in self.axes:
            ax.set_facecolor("#12151f")
            ax.tick_params(colors=DIM, labelsize=7)
            for spine in ax.spines.values():
                spine.set_edgecolor("#2e3147")

        self.canvas = FigureCanvasTkAgg(self.fig, master=outer)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=6, pady=4)
        self._draw_placeholder_graphs()

    def _draw_placeholder_graphs(self):
        titles = [
            "1. Success / Failure / Forgery Rate",
            "2. Signing Time vs Key Size",
            "3. Auth Success Rate (Before vs After)",
            "4. Latency: Secure vs Insecure",
        ]
        for ax, title in zip(self.axes, titles):
            ax.clear()
            ax.set_facecolor("#12151f")
            ax.set_title(title, color=TEXT, fontsize=7, pad=4)
            ax.text(0.5, 0.45, "Run tests to populate",
                    ha="center", va="center", color=DIM, fontsize=7,
                    transform=ax.transAxes)
            for spine in ax.spines.values():
                spine.set_edgecolor("#2e3147")
        self.canvas.draw()

    def _gen_keys(self):
        _clear(self.log)
        self.keys = generate_keys()
        k = self.keys
        _append(self.log, "=" * 68, ACCENT)
        _append(self.log, "  KEY GENERATION", ACCENT)
        _append(self.log, "=" * 68, ACCENT)
        _append(self.log, f"  Prime p     = {k['p']}", TEXT)
        _append(self.log, f"  Generator g = {k['g']}", TEXT)
        _append(self.log, f"  Private key x = {k['x']}", GOLD)
        _append(self.log, f"  Public  key y = g^x mod p = {k['y']}", GRN_CLR)
        _append(self.log, "")

        self.key_info.configure(state="normal")
        self.key_info.delete("1.0", tk.END)
        self.key_info.insert(tk.END,
            f"p = {k['p']}\ng = {k['g']}\nx = {k['x']}\ny = {k['y']}")
        self.key_info.configure(state="disabled")

        for btn in (self.btn_attack, self.btn_fix, self.btn_graph):
            btn.configure(state="normal")

    def _run_attack(self):
        if not self.keys:
            return
        self.btn_attack.configure(state="disabled")
        threading.Thread(target=self._run_attack_thread, daemon=True).start()

    def _run_attack_thread(self):
        _clear(self.log)
        _append(self.log, "=" * 68, RED_CLR)
        _append(self.log, "  PHASE 1 - BEFORE FIX  (25 test cases)", RED_CLR)
        _append(self.log, "=" * 68, RED_CLR)

        results = run_before_fix(self.keys)
        self.before_data = results

        for r in results:
            self._print_result(r)

        broken = sum(1 for r in results if r["label"] == "BROKEN")
        forged = sum(1 for r in results
                     if r["label"] == "FORGED" or
                        (r.get("attack") and r["attack"] and r["attack"].get("verified")))
        secure = sum(1 for r in results if r["label"] == "SECURE")
        total  = len(results)
        success_rate = (secure / total * 100) if total else 0.0

        self.stat_vars["broken_before"].set(f"{broken}/{total}")
        self.stat_vars["forged_before"].set(f"{forged}/{total}")
        self.stat_vars["secure_before"].set(f"{secure}/{total}")

        _append(self.log, "")
        _append(self.log, "-" * 68, DIM)
        _append(self.log, "  Before Fix Summary:", GOLD)
        _append(self.log, f"  BROKEN  : {broken}/{total}", RED_CLR)
        _append(self.log, f"  FORGED  : {forged}/{total}", ORG_CLR)
        _append(self.log, f"  SECURE  : {secure}/{total}", GRN_CLR)
        _append(self.log, f"  SUCCESS RATE: {success_rate:.2f}%", GOLD)
        _append(self.log, "-" * 68, DIM)

        self.btn_attack.configure(state="normal")

    def _run_fix(self):
        if not self.keys:
            return
        self.btn_fix.configure(state="disabled")
        threading.Thread(target=self._run_fix_thread, daemon=True).start()

    def _run_fix_thread(self):
        _append(self.log, "")
        _append(self.log, "=" * 68, GRN_CLR)
        _append(self.log, "  PHASE 2 - AFTER FIX  (25 test cases with prevention)", GRN_CLR)
        _append(self.log, "  Prevention: gcd(k, Q)=1 enforced and k is never reused", GRN_CLR)
        _append(self.log, "=" * 68, GRN_CLR)

        results = run_after_fix(self.keys)
        self.after_data = results

        for r in results:
            self._print_result(r)

        broken = sum(1 for r in results if r["label"] == "BROKEN")
        forged = sum(1 for r in results if r["label"] == "FORGED")
        secure = sum(1 for r in results if r["label"] == "SECURE")
        total  = len(results)
        success_rate = (secure / total * 100) if total else 0.0

        self.stat_vars["broken_after"].set(f"{broken}/{total}")
        self.stat_vars["forged_after"].set(f"{forged}/{total}")
        self.stat_vars["secure_after"].set(f"{secure}/{total}")

        _append(self.log, "")
        _append(self.log, "-" * 68, DIM)
        _append(self.log, "  After Fix Summary:", GOLD)
        _append(self.log, f"  BROKEN : {broken}/{total}  (0% failure rate)", RED_CLR)
        _append(self.log, f"  FORGED : {forged}/{total}  (0% forgery rate)", ORG_CLR)
        _append(self.log, f"  SECURE : {secure}/{total}  (100% secure)", GRN_CLR)
        _append(self.log, f"  SUCCESS RATE: {success_rate:.2f}%", GOLD)
        _append(self.log, "-" * 68, DIM)

        self.btn_fix.configure(state="normal")

    def _show_graphs(self):
        self.btn_graph.configure(state="disabled")
        threading.Thread(target=self._build_graphs_thread, daemon=True).start()

    def _build_graphs_thread(self):
        _append(self.log, "\nCollecting benchmark data, please wait...", GOLD)
        self.bench_data = run_timing_benchmark(n_samples=8)
        self.overhead   = run_overhead_benchmark(self.keys, n=40)
        _append(self.log, "Benchmarks complete. Drawing graphs...", GRN_CLR)
        self.after(0, self._redraw_graphs)
        self.btn_graph.configure(state="normal")

    def _redraw_graphs(self):
        for ax in self.axes:
            ax.clear()
            ax.set_facecolor("#12151f")
            for spine in ax.spines.values():
                spine.set_edgecolor("#2e3147")
            ax.tick_params(colors=DIM, labelsize=7)

        self._draw_rate_chart()
        self._draw_timing_chart()
        self._draw_auth_chart()
        self._draw_overhead_chart()
        self.canvas.draw()

    def _draw_rate_chart(self):
        ax = self.axes[0]
        ax.set_title("1. Success / Failure / Forgery Rate", color=TEXT,
                     fontsize=7.5, pad=4)

        def counts(data):
            broken = sum(1 for r in data if r["label"] == "BROKEN")
            forged = sum(1 for r in data
                         if r["label"] == "FORGED" or
                            (r.get("attack") and r["attack"] and r["attack"].get("verified")))
            secure = sum(1 for r in data if r["label"] == "SECURE")
            return broken, forged, secure

        bb, fb, sb = counts(self.before_data or [])
        ba, fa, sa = counts(self.after_data  or [])

        x      = [0, 1, 2]
        width  = 0.35
        labels = ["Broken", "Forged", "Secure"]

        bars1 = ax.bar([xi - width/2 for xi in x], [bb, fb, sb],
                       width, label="Before", color=[RED_CLR, ORG_CLR, "#2980b9"])
        bars2 = ax.bar([xi + width/2 for xi in x], [ba, fa, sa],
                       width, label="After",  color=["#7f1a1a", "#7f4a00", GRN_CLR])

        ax.set_xticks(x)
        ax.set_xticklabels(labels, color=TEXT, fontsize=7)
        ax.set_ylabel("Count", color=DIM, fontsize=7)
        ax.legend(fontsize=6, facecolor=PANEL, labelcolor=TEXT, loc="upper right")

        for bar in list(bars1) + list(bars2):
            h = bar.get_height()
            if h:
                ax.text(bar.get_x() + bar.get_width()/2, h + 0.1,
                        str(int(h)), ha="center", fontsize=6, color=TEXT)

    def _draw_timing_chart(self):
        ax = self.axes[1]
        ax.set_title("2. Signing Time vs Key Size", color=TEXT, fontsize=7.5, pad=4)

        if not self.bench_data:
            ax.text(0.5, 0.45, "No data", ha="center", va="center",
                    color=DIM, fontsize=7, transform=ax.transAxes)
            return

        labels = [d[0] for d in self.bench_data]
        times  = [d[1] for d in self.bench_data]

        ax.plot(labels, times, marker="o", color=ACCENT, linewidth=1.5, markersize=4)
        ax.fill_between(range(len(labels)), times, alpha=0.15, color=ACCENT)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, color=TEXT, fontsize=6.5)
        ax.set_ylabel("Avg Time (ms)", color=DIM, fontsize=7)

    def _draw_auth_chart(self):
        ax = self.axes[2]
        ax.set_title("3. Auth Success Rate (Before vs After)", color=TEXT,
                     fontsize=7.5, pad=4)

        def cumulative_rate(data):
            rates, success = [], 0
            for i, r in enumerate(data, 1):
                if r["label"] == "SECURE":
                    success += 1
                rates.append(success / i * 100)
            return rates

        if self.before_data:
            ax.plot(range(1, len(self.before_data)+1),
                    cumulative_rate(self.before_data),
                    color=RED_CLR, linewidth=1.5, label="Before")
        if self.after_data:
            ax.plot(range(1, len(self.after_data)+1),
                    cumulative_rate(self.after_data),
                    color=GRN_CLR, linewidth=1.5, label="After")

        ax.set_ylabel("Cumulative Success %", color=DIM, fontsize=7)
        ax.set_xlabel("Test Case number", color=DIM, fontsize=7)
        ax.set_ylim(0, 110)
        ax.legend(fontsize=6, facecolor=PANEL, labelcolor=TEXT)

    def _draw_overhead_chart(self):
        ax = self.axes[3]
        ax.set_title("4. Latency: Secure vs Insecure Signing", color=TEXT,
                     fontsize=7.5, pad=4)

        insecure_ms, secure_ms = self.overhead
        if insecure_ms is None:
            ax.text(0.5, 0.45, "No data", ha="center", va="center",
                    color=DIM, fontsize=7, transform=ax.transAxes)
            return

        labels = ["Insecure\n(no check)", "Secure\n(gcd + unique k)"]
        vals   = [insecure_ms, secure_ms]
        bars   = ax.bar(labels, vals, color=[RED_CLR, GRN_CLR], width=0.45)
        ax.set_ylabel("Avg Time (ms)", color=DIM, fontsize=7)

        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2,
                    v + max(vals) * 0.02,
                    f"{v:.4f} ms", ha="center", fontsize=6.5, color=TEXT)

    def _print_result(self, r):
        label   = r.get("label", "unknown")
        test_no = r.get("test_no", "?")
        msg     = r.get("message", "")
        m       = r.get("message_hash", "?")
        k       = r.get("k", "?")
        gcd_k   = r.get("gcd_k", "?")

        colour = GRN_CLR if label == "SECURE" else (
                 RED_CLR if label == "BROKEN" else ORG_CLR)

        _append(self.log,
                f"\n[Test {test_no:02d}]  {label}  |  Message: \"{msg}\"", colour)
        _append(self.log,
            f"  hash(m) = {m}   k = {k}   gcd(k, Q) = {gcd_k}", DIM)

        sig = r.get("sig", {})

        if label == "BROKEN":
            _append(self.log, f"  {r.get('detail', '')}", RED_CLR)
            _append(self.log, "  Signature is UNDEFINED. s cannot be computed.", RED_CLR)

        elif label in ("REUSED", "REUSED (first)"):
            _append(self.log,
                    f"  Signed with reused k={k}.  r={sig.get('r','?')}  s={sig.get('s','?')}",
                    ORG_CLR)
            if r.get("attack") and r["attack"].get("success"):
                _append(self.log, "  Attack Steps:", ORG_CLR)
                for line in r["attack"]["steps"]:
                    _append(self.log, line, ORG_CLR)

        elif label == "FORGED":
            atk = r.get("attack", {})
            if atk:
                _append(self.log,
                        f"  Private key recovered. x_recovered = {atk.get('x_recovered', '?')}",
                        ORG_CLR)
                _append(self.log, "  Full Attack Log:", ORG_CLR)
                for line in atk.get("steps", []):
                    _append(self.log, line, ORG_CLR)

        else:
            _append(self.log,
                    f"  r={sig.get('r','?')}  s={sig.get('s','?')}", GRN_CLR)
            _append(self.log,
                    f"  Verification: {'PASSED' if r.get('verified') else 'FAILED'}",
                    GRN_CLR if r.get("verified") else RED_CLR)
            _append(self.log, f"  {r.get('detail', '')}", DIM)


if __name__ == "__main__":
    app = ElGamalApp()
    app.mainloop()
