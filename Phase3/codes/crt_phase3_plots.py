# crt_phase3_plots.py
# Generate publication-ready plots for Asmuth–Bloom (CRT) Phase-3 security analysis.
# Depends on: crt_phase3_tests.py (same directory)
# Python 3.10+, matplotlib, standard library

import os
import math
import random
import csv
from collections import Counter
import matplotlib.pyplot as plt

from crt_phase3_tests import (
    test_partial_uniformity,
    test_inequality_violation_leakage,
    test_redundancy_vs_loss,
    test_corruption_effect,
    test_malicious_dealer_inconsistency,
    test_noise_sensitivity,
    test_candidate_count_below_threshold,
    moduli_with_margin,
    encode_share_set,
    crt_list
)

# -------------------------
# Config
# -------------------------
OUT_DIR = "results/crt_phase3"
os.makedirs(OUT_DIR, exist_ok=True)

# Default parameters (edit as needed)
M0 = 101
T  = 5
N  = 7
SEED = 0

# -------------------------
# Helpers
# -------------------------
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

# -------------------------
# 1) Partial uniformity (k < t)
# -------------------------
def plot_partial_uniformity(m0=M0, t=T, n=N, k=2, trials=2000, max_bins=80):
    random.seed(SEED)
    res = test_partial_uniformity(m0, t, n, trials=trials, k=k)
    # For visualization: sample the CRT values again and histogram a projection (mod a small number)
    # because M_k is large and hist would be sparse. Project to mod P to show flatness.
    P = 47  # small prime for projection
    moduli = moduli_with_margin(m0, t, n, margin_factor=4.0)
    m_k = [moduli[i] for i in range(1, k + 1)]
    buckets = Counter()
    for _ in range(trials):
        s = random.randrange(0, m0)
        _, shares = encode_share_set(s, m0, moduli, t)
        residues = [ri for (mi, ri) in shares[:k]]
        xk, _ = crt_list(residues, m_k)
        buckets[xk % P] += 1

    xs = list(range(P))
    ys = [buckets.get(x, 0) for x in xs]
    plt.figure()
    plt.bar(xs, ys)
    plt.xlabel(f"CRT value modulo {P}")
    plt.ylabel("Count")
    plt.title(f"Partial uniformity (k={k} < t). AB inequality OK.")
    savefig(os.path.join(OUT_DIR, f"crt_partial_uniformity_k{k}.png"))

    # also write summary CSV
    write_csv(os.path.join(OUT_DIR, f"crt_partial_uniformity_k{k}.csv"),
              ["inequality_ok","M_k","unique_bins","chisq","entropy_bits","entropy_uniform_bits"],
              [[res["inequality_ok"], res["M_k"], res["unique_bins"], f"{res['chisq']:.3f}",
                f"{res['entropy_bits']:.4f}", f"{res['entropy_uniform_bits']:.4f}"]])

# -------------------------
# 2) Inequality violation leakage (k = t-1)
# -------------------------
def plot_violation_leakage(m0=M0, t=T, n=N, trials=1000, violation_factor=1.05):
    random.seed(SEED)
    res = test_inequality_violation_leakage(m0, t, n, trials=trials, violation_factor=violation_factor)
    hit = res["hit_rate"]
    base = res["baseline"]

    plt.figure()
    plt.bar(["baseline (1/m0)", "observed hit"], [base, hit])
    plt.ylim(0, max(hit, base) * 1.3)
    plt.ylabel("Probability")
    plt.title(f"Inequality violation leakage (k=t-1). AB inequality violated.")
    savefig(os.path.join(OUT_DIR, f"crt_violation_leakage.png"))

    write_csv(os.path.join(OUT_DIR, f"crt_violation_leakage.csv"),
              ["inequality_ok","hit_rate","baseline","moduli"],
              [[res["inequality_ok"], f"{hit:.6f}", f"{base:.6f}", " ".join(map(str,res["moduli"]))]])

# -------------------------
# 3) Redundancy vs loss curve
# -------------------------
def plot_redundancy_curve(m0=M0, t=T, n=N, trials=800):
    random.seed(SEED)
    loss_fracs = [0.0,0.1,0.2,0.3,0.4,0.5,0.6]
    rows = test_redundancy_vs_loss(m0, t, n, loss_fracs, trials=trials)
    xs = [r["loss_frac"] for r in rows]
    ys = [r["success_rate"] for r in rows]
    plt.figure()
    plt.plot(xs, ys, marker="o")
    plt.xlabel("Share loss fraction")
    plt.ylabel("Reconstruction success rate")
    plt.title("Redundancy vs loss (threshold fragility)")
    savefig(os.path.join(OUT_DIR, f"crt_redundancy_curve.png"))

    write_csv(os.path.join(OUT_DIR, f"crt_redundancy_curve.csv"),
              ["loss_frac","success_rate"],
              [[r["loss_frac"], f"{r['success_rate']:.6f}"] for r in rows])

# -------------------------
# 4) Corruption effect (non-verifiability / wrong output)
# -------------------------
def plot_corruption_effect(m0=M0, t=T, n=N, corr_prob=0.15, trials=1000):
    random.seed(SEED)
    res = test_corruption_effect(m0, t, n, corr_prob=corr_prob, trials=trials)
    plt.figure()
    plt.bar(["exact","wrong","fail"], [res["exact_rate"], res["wrong_rate"], res["fail_rate"]])
    plt.ylim(0, 1.0)
    plt.ylabel("Fraction")
    plt.title(f"Effect of corrupted shares (p_corrupt={corr_prob})")
    savefig(os.path.join(OUT_DIR, f"crt_corruption_effect.png"))

    write_csv(os.path.join(OUT_DIR, f"crt_corruption_effect.csv"),
              ["corr_prob","exact_rate","wrong_rate","fail_rate"],
              [[res["corr_prob"], f"{res['exact_rate']:.6f}", f"{res['wrong_rate']:.6f}", f"{res['fail_rate']:.6f}"]])

# -------------------------
# 5) Malicious dealer inconsistency
# -------------------------
def plot_malicious_dealer(m0=M0, t=T, n=N, trials=600):
    random.seed(SEED)
    res = test_malicious_dealer_inconsistency(m0, t, n, trials=trials)
    plt.figure()
    plt.bar(["inconsistent subsets"], [res["inconsistent_fraction"]])
    plt.ylim(0, 1.0)
    plt.ylabel("Fraction")
    plt.title("Malicious dealer: inconsistent reconstructions across subsets")
    savefig(os.path.join(OUT_DIR, f"crt_malicious_dealer.png"))

    write_csv(os.path.join(OUT_DIR, f"crt_malicious_dealer.csv"),
              ["inconsistent_fraction","note"],
              [[f"{res['inconsistent_fraction']:.6f}", res["note"]]])

# -------------------------
# 6) Noise sensitivity curve
# -------------------------
def plot_noise_sensitivity(m0=M0, t=T, n=N, max_noise=10, trials=600):
    random.seed(SEED)
    rows = test_noise_sensitivity(m0, t, n, max_noise=max_noise, trials=trials)
    xs = [r["noise_bound"] for r in rows]
    ys = [r["success_rate"] for r in rows]
    plt.figure()
    plt.plot(xs, ys, marker="o")
    plt.xlabel("Additive noise bound d (perturb 1 share by [-d, d])")
    plt.ylabel("Reconstruction success rate")
    plt.title("Noise sensitivity (brittleness to residue errors)")
    savefig(os.path.join(OUT_DIR, f"crt_noise_sensitivity.png"))

    write_csv(os.path.join(OUT_DIR, f"crt_noise_sensitivity.csv"),
              ["noise_bound","success_rate"],
              [[r["noise_bound"], f"{r['success_rate']:.6f}"] for r in rows])

# -------------------------
# 7) Candidate count below threshold (safe vs violated)
# -------------------------
def plot_candidate_count(m0=M0, t=T, n=N, k=None, trials=600):
    random.seed(SEED)
    if k is None: k = t - 1
    res = test_candidate_count_below_threshold(m0, t, n, k=k, trials=trials)
    safe  = res["avg_candidates_safe"]
    bad   = res["avg_candidates_violated"]
    theory = res["theory_safe"]

    plt.figure()
    plt.bar(["safe (AB ok)","violated"], [safe, bad])
    plt.axhline(theory, linestyle="--")
    plt.ylabel("Avg candidate secrets in Z_m0")
    plt.title(f"Candidate count with k={k} < t")
    savefig(os.path.join(OUT_DIR, f"crt_candidate_count_k{k}.png"))

    write_csv(os.path.join(OUT_DIR, f"crt_candidate_count_k{k}.csv"),
              ["inequality_ok","inequality_bad","avg_candidates_safe","avg_candidates_violated","theory_safe"],
              [[res["inequality_ok"], res["inequality_bad"], f"{safe:.4f}", f"{bad:.4f}", theory]])

# -------------------------
# Main
# -------------------------
def main():
    print("Generating CRT Phase-3 plots into:", OUT_DIR)
    plot_partial_uniformity(k=2, trials=2000)
    plot_violation_leakage(trials=1000, violation_factor=1.05)
    plot_redundancy_curve(trials=800)
    plot_corruption_effect(corr_prob=0.15, trials=1000)
    plot_malicious_dealer(trials=600)
    plot_noise_sensitivity(max_noise=10, trials=600)
    plot_candidate_count(k=T-1, trials=600)
    print("Done.")

if __name__ == "__main__":
    main()
