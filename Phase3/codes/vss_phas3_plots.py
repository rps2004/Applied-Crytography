# vss_phase3_plots.py
# Generate plots for Feldman & Pedersen VSS Phase-3 security analysis.
# Depends on: vss_phase3_tests.py (same directory)
# Python 3.10+, matplotlib only.

import os
import random
import csv
import matplotlib.pyplot as plt

from vss_phase3_tests import (
    demo_group_small,
    test_dealer_cheating_feldman,
    test_participant_forgery_feldman,
    test_dealer_cheating_pedersen,
    test_participant_forgery_pedersen,
    test_randomness_reuse_pedersen_recoverable,
    test_timing_commit_verify,
)

OUT_DIR = "results/vss_phase3"
os.makedirs(OUT_DIR, exist_ok=True)

SEED = 0
random.seed(SEED)

# Default demo params (match your run)
p, q, g = demo_group_small()
# Simple h of same order as g (the test file chooses the first suitable)
h = 3 if 3 != g else 4
t_default = 3
n_default = 6

def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)

def savefig(path):
    plt.tight_layout()
    plt.savefig(path, bbox_inches="tight", dpi=200)
    plt.close()

# 1) Detection rate: Feldman vs Pedersen (dealer cheating)
def plot_detection_rates(trials=400, t=t_default, n=n_default):
    f_res = test_dealer_cheating_feldman(p, q, g, t, n, trials=trials)
    p_res = test_dealer_cheating_pedersen(p, q, g, h, t, n, trials=trials)
    vals = [f_res["avg_detection_rate"], p_res["avg_detection_rate"]]
    plt.figure()
    plt.bar(["Feldman", "Pedersen"], vals)
    plt.ylim(0, 1.0)
    plt.ylabel("Avg detection rate")
    plt.title("Dealer cheating detection (VSS)")
    savefig(os.path.join(OUT_DIR, "vss_detection_rate.png"))
    write_csv(os.path.join(OUT_DIR, "vss_detection_rate.csv"),
              ["scheme","avg_detection_rate","trials","t","n"],
              [["Feldman", f"{vals[0]:.6f}", trials, t, n],
               ["Pedersen", f"{vals[1]:.6f}", trials, t, n]])

# 2) Forgery pass rate: Feldman vs Pedersen (participant forging)
def plot_forgery_rates(trials=200, attempts=50, t=t_default, n=n_default):
    f_res = test_participant_forgery_feldman(p, q, g, t, n, trials=trials)
    p_res = test_participant_forgery_pedersen(p, q, g, h, t, n, trials=trials)
    vals = [f_res["avg_forge_pass_rate"], p_res["avg_forge_pass_rate"]]
    plt.figure()
    plt.bar(["Feldman", "Pedersen"], vals)
    plt.ylim(0, 1.0)
    plt.ylabel("Avg forgery pass rate")
    plt.title("Participant forgery (pass probability)")
    savefig(os.path.join(OUT_DIR, "vss_forgery_rate.png"))
    write_csv(os.path.join(OUT_DIR, "vss_forgery_rate.csv"),
              ["scheme","avg_forge_pass_rate","trials","attempts","t","n"],
              [["Feldman", f"{vals[0]:.6f}", trials, attempts, t, n],
               ["Pedersen", f"{vals[1]:.6f}", trials, attempts, t, n]])

# 3) Randomness reuse demo (Pedersen)
def plot_randomness_reuse(trials=200, t=t_default, n=n_default):
    res = test_randomness_reuse_pedersen_recoverable(p, q, g, h, t, n, trials=trials)
    frac = res["recovery_success_fraction"]
    plt.figure()
    plt.bar(["recovery success fraction"], [frac])
    plt.ylim(0, 1.0)
    plt.ylabel("Fraction")
    plt.title("Pedersen randomness reuse: recovery feasibility (demo group)")
    savefig(os.path.join(OUT_DIR, "vss_pedersen_reuse.png"))
    write_csv(os.path.join(OUT_DIR, "vss_pedersen_reuse.csv"),
              ["recovery_success_fraction","examples_count"],
              [[f"{frac:.6f}", len(res["recovered_examples"])]])
    # also dump a few examples for appendix
    with open(os.path.join(OUT_DIR, "vss_pedersen_reuse_examples.txt"), "w", encoding="utf-8") as f:
        for ex in res["recovered_examples"]:
            f.write(str(ex) + "\n")

# 4) Timing vs t (commit/verify)
def plot_timing_vs_t(t_values=(2,3,4,5,6), n=n_default, trials=60):
    rows = test_timing_commit_verify(p, q, g, h, list(t_values), n=n, trials=trials)
    # Four separate plots (one per metric) — no subplots
    xs = [r["t"] for r in rows]

    plt.figure()
    plt.plot(xs, [r["feldman_commit_avg_s"] for r in rows], marker="o")
    plt.xlabel("t (threshold)")
    plt.ylabel("Seconds")
    plt.title("Feldman: commitment time vs t")
    savefig(os.path.join(OUT_DIR, "vss_time_feldman_commit.png"))

    plt.figure()
    plt.plot(xs, [r["feldman_verify_all_avg_s"] for r in rows], marker="o")
    plt.xlabel("t (threshold)")
    plt.ylabel("Seconds")
    plt.title("Feldman: verify-all time vs t")
    savefig(os.path.join(OUT_DIR, "vss_time_feldman_verify.png"))

    plt.figure()
    plt.plot(xs, [r["pedersen_commit_avg_s"] for r in rows], marker="o")
    plt.xlabel("t (threshold)")
    plt.ylabel("Seconds")
    plt.title("Pedersen: commitment time vs t")
    savefig(os.path.join(OUT_DIR, "vss_time_pedersen_commit.png"))

    plt.figure()
    plt.plot(xs, [r["pedersen_verify_all_avg_s"] for r in rows], marker="o")
    plt.xlabel("t (threshold)")
    plt.ylabel("Seconds")
    plt.title("Pedersen: verify-all time vs t")
    savefig(os.path.join(OUT_DIR, "vss_time_pedersen_verify.png"))

    # CSV
    with open(os.path.join(OUT_DIR, "vss_time_vs_t.csv"), "w", newline="", encoding="utf-8") as f:
        header = ["t","feldman_commit_avg_s","feldman_verify_all_avg_s","pedersen_commit_avg_s","pedersen_verify_all_avg_s","n"]
        w = csv.writer(f); w.writerow(header)
        for r in rows:
            w.writerow([r[h] for h in header])

def main():
    print("Generating VSS Phase-3 plots into:", OUT_DIR)
    plot_detection_rates()
    plot_forgery_rates()
    plot_randomness_reuse()
    plot_timing_vs_t()
    print("Done.")

if __name__ == "__main__":
    main()
