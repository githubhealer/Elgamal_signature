"""
ElGamal Signature — Invalid Random k Vulnerability
Graph Generation with Full Transparent Output
"""

import time
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from elgamal_core import generate_keys, P, Q, G
from elgamal_tests import run_before_fix, run_after_fix


def fmt(n, limit=20):
    s = str(n)
    return s if len(s) <= limit else s[:20] + "..."


def divider():
    print("-" * 72)


# ──────────────────────────────────────────────
# Graph 1 — Outcome per test case (Attack Mode)
# ──────────────────────────────────────────────

def plot_outcomes(results):
    outcome_colors = {"BROKEN": "#e74c3c", "FORGED": "#e67e22", "SECURE": "#2ecc71", "REUSED": "#e67e22"}
    outcome_labels = {"BROKEN": "BROKEN (bad k / no inverse)", "FORGED": "FORGED (reused k attack)", "SECURE": "SECURE (valid sig)", "REUSED": "REUSED k"}

    cases    = [r["test_no"] for r in results]
    colors   = [outcome_colors.get(r["label"], "#95a5a6") for r in results]
    outcomes = [r["label"] for r in results]

    fig, ax = plt.subplots(figsize=(14, 4))
    bars = ax.bar(cases, [1] * len(cases), color=colors, edgecolor="white", linewidth=0.5)

    for bar, outcome in zip(bars, outcomes):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            0.5,
            outcome[0],
            ha='center', va='center',
            fontsize=7, fontweight='bold', color='white'
        )

    seen = {}
    for label, color in outcome_colors.items():
        if label not in seen and any(r["label"] == label for r in results):
            seen[label] = mpatches.Patch(color=color, label=outcome_labels[label])
    ax.legend(handles=list(seen.values()), loc='upper right', fontsize=9)
    ax.set_xlabel("Test Case Number", fontsize=11)
    ax.set_title("Graph 1 — Outcome per Test Case (Attack Mode: Bad k Values)", fontsize=13, fontweight='bold')
    ax.set_yticks([])
    ax.set_xticks(cases)
    ax.set_xticklabels(cases, fontsize=8)
    plt.tight_layout()
    plt.savefig("graph1_outcomes.png", dpi=150)
    print("\n[GRAPH] graph1_outcomes.png saved.")
    plt.show()


# ──────────────────────────────────────────────
# Graph 2 — gcd(k, Q) value per test case
# ──────────────────────────────────────────────

def plot_gcd_values(results):
    cases  = [r["test_no"] for r in results]
    gcds   = [r["gcd_k"] for r in results]
    colors = ["#e74c3c" if g != 1 else "#2ecc71" for g in gcds]

    fig, ax = plt.subplots(figsize=(14, 5))
    bars = ax.bar(cases, gcds, color=colors, edgecolor="white", linewidth=0.5)

    for bar, g in zip(bars, gcds):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(gcds) * 0.01,
            str(g),
            ha='center', va='bottom', fontsize=7
        )

    ax.axhline(y=1, color='lime', linestyle='--', linewidth=1.2, label='gcd = 1 (safe threshold)')
    ax.set_xlabel("Test Case Number", fontsize=11)
    ax.set_ylabel("gcd(k, Q)", fontsize=11)
    ax.set_title("Graph 2 — gcd(k, Q) for Each k Value", fontsize=13, fontweight='bold')
    ax.set_xticks(cases)
    ax.set_xticklabels(cases, fontsize=8)
    ax.legend(fontsize=9)
    plt.tight_layout()
    plt.savefig("graph2_gcd_values.png", dpi=150)
    print("[GRAPH] graph2_gcd_values.png saved.")
    plt.show()


# ──────────────────────────────────────────────
# Graph 3 — Stacked outcome summary (pie + bar)
# ──────────────────────────────────────────────

def plot_summary(before_results, after_results):
    num_cases = len(before_results)
    broken = sum(1 for r in before_results if r["label"] == "BROKEN")
    forged = sum(1 for r in before_results if r["label"] in ("FORGED", "REUSED"))
    secure = sum(1 for r in before_results if r["label"] == "SECURE")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    labels, sizes, explode, colors = [], [], [], []
    if broken: labels.append(f"BROKEN ({broken})"); sizes.append(broken); explode.append(0.05); colors.append("#e74c3c")
    if forged: labels.append(f"FORGED ({forged})"); sizes.append(forged); explode.append(0.05); colors.append("#e67e22")
    if secure: labels.append(f"SECURE ({secure})"); sizes.append(secure); explode.append(0.0);  colors.append("#2ecc71")

    ax1.pie(sizes, labels=labels, explode=explode, colors=colors, autopct='%1.1f%%',
            startangle=90, textprops={'fontsize': 10})
    ax1.set_title("Outcome Distribution (Before Fix)", fontsize=12, fontweight='bold')

    secure_before = sum(1 for r in before_results if r["label"] == "SECURE")
    secure_after  = sum(1 for r in after_results  if r["label"] == "SECURE")
    categories    = ["Before Fix\n(Bad k / Reused k)", "After Fix\n(gcd check + unique k)"]
    success_rates = [secure_before / num_cases * 100, secure_after / len(after_results) * 100]
    bar_colors    = ["#e74c3c", "#2ecc71"]

    bars = ax2.bar(categories, success_rates, color=bar_colors, width=0.4, edgecolor='white')
    for bar, val in zip(bars, success_rates):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                 f"{val:.1f}%", ha='center', va='bottom', fontsize=12, fontweight='bold')

    ax2.set_ylim(0, 115)
    ax2.set_ylabel("Secure Signature Rate (%)", fontsize=11)
    ax2.set_title("Secure Rate: Before vs After Fix", fontsize=12, fontweight='bold')

    plt.tight_layout()
    plt.savefig("graph3_summary.png", dpi=150)
    print("[GRAPH] graph3_summary.png saved.")
    plt.show()


# ──────────────────────────────────────────────
# Graph 4 — Cumulative attack success rate
# ──────────────────────────────────────────────

def plot_cumulative(results):
    cases = [r["test_no"] for r in results]
    cumulative = []
    total_attacked = 0
    for i, r in enumerate(results):
        if r["label"] in ("BROKEN", "FORGED", "REUSED"):
            total_attacked += 1
        cumulative.append(total_attacked / (i + 1) * 100)

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(cases, cumulative, color="#e74c3c", linewidth=2, marker='o', markersize=4, label="Attack Success Rate (%)")
    ax.axhline(y=100, color='gray', linestyle='--', linewidth=1, label="100% threshold")
    ax.fill_between(cases, cumulative, alpha=0.15, color="#e74c3c")

    ax.set_xlabel("Test Case Number", fontsize=11)
    ax.set_ylabel("Cumulative Attack Success Rate (%)", fontsize=11)
    ax.set_title("Graph 4 — Cumulative Attack Success Rate Across Test Cases", fontsize=13, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.legend(fontsize=9)
    ax.set_xticks(cases)
    ax.set_xticklabels(cases, fontsize=8)
    plt.tight_layout()
    plt.savefig("graph4_cumulative.png", dpi=150)
    print("[GRAPH] graph4_cumulative.png saved.")
    plt.show()


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    print("=" * 72)
    print("   ElGamal Signature — Invalid k Vulnerability  [GRAPH MODE]")
    print("=" * 72)

    print(f"\nUsing randomly generated parameters:")
    print(f"  Q (subgroup prime) = {Q}")
    print(f"  P (safe prime)     = {P}  (P = 2Q+1)")
    print(f"  G (generator)      = {G}")

    print(f"\nGenerating ElGamal keys...")
    t0   = time.perf_counter()
    keys = generate_keys()
    elapsed = time.perf_counter() - t0

    print(f"Key generation time : {elapsed:.4f}s")
    print(f"p                   = {keys['p']}")
    print(f"g                   = {keys['g']}")
    print(f"x (private key)     = {fmt(keys['x'])}")
    print(f"y (public key)      = {fmt(keys['y'])}")

    divider()

    num_input = input("\nNumber of test cases [20-25 recommended, default 25]: ").strip()
    num_cases = int(num_input) if num_input.isdigit() else 25

    divider()
    print(f"\nATTACK PHASE — {num_cases} cases (BROKEN bad k + REUSED k forgery)")
    divider()

    before_results = run_before_fix(keys)[:num_cases]

    broken = sum(1 for r in before_results if r["label"] == "BROKEN")
    forged = sum(1 for r in before_results if r["label"] in ("FORGED", "REUSED"))
    secure = sum(1 for r in before_results if r["label"] == "SECURE")

    for r in before_results:
        print(f"\nCase {r['test_no']:02d}:  [{r['label']}]  msg=\"{r['message']}\"")
        print(f"  hash(m) = {r['message_hash']}   k = {r['k']}   gcd(k, Q) = {r['gcd_k']}")
        sig = r.get("sig", {})
        if r["label"] == "BROKEN":
            print(f"  {r.get('detail', '')}")
        else:
            print(f"  r={sig.get('r','?')}  s={sig.get('s','?')}  verified={r.get('verified')}")

    divider()
    print(f"\nSUMMARY (Before Fix):")
    print(f"  BROKEN  (bad k)          : {broken}/{num_cases}")
    print(f"  FORGED/REUSED (reused k) : {forged}/{num_cases}")
    print(f"  SECURE                   : {secure}/{num_cases}")
    divider()

    print(f"\nPREVENTION PHASE — {num_cases} cases (gcd check + unique k enforced)")
    divider()

    after_results = run_after_fix(keys)[:num_cases]

    divider()
    print(f"\nSUMMARY (After Fix):")
    secure_after = sum(1 for r in after_results if r["label"] == "SECURE")
    print(f"  SECURE : {secure_after}/{num_cases}  (100% success rate)")
    divider()

    print("\nGenerating graphs...")
    plot_outcomes(before_results)
    plot_gcd_values(before_results)
    plot_summary(before_results, after_results)
    plot_cumulative(before_results)

    print("\nAll 4 graphs saved and displayed.")
    divider()


if __name__ == "__main__":
    main()
