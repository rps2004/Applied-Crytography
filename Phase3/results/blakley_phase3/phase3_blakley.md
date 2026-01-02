# Phase 3 — Security Analysis: Blakley's Secret Sharing

## Theory (short)
- Each share defines an affine hyperplane; k independent shares reduce secret-space size from $p^t$ to $p^{t-k}$.
- Leakage per independent share: $\log_2 p$ bits.

## Experiments (figures saved in results/blakley_phase3/)
1. **Leakage vs k** — `leakage_p{p}_t{t}.png` for each (p,t). Shows I(S;shares) ≈ k·log2(p).
2. **Rank-failure heatmap** — `rank_failure_heatmap.png`. Shows probability rank(A)<t for small primes/larger t.
3. **DoS single vs multi** — `dos_compare_p101_t4.png` + `dos_single_vs_multi.csv`.
4. **Coordinate entropy** — `coord_entropy_p{p}_t{t}.png` showing posterior entropy decline vs k.

## Key findings (to expand in report)
- Empirical leakage matches theory: ~log2(p) bits per independent share.
- Rank failures (availability risk) increase when p is small relative to t. See heatmap.
- A single corrupted share can break reconstruction if unlucky (single-shot); trying multiple subsets dramatically improves recovery but is not a substitute for verifiability.
- Coordinate leakage is driven by coefficient sparsity; enforce dense uniform coefficients to avoid bias.

## Suggested mitigations
- Add commitment layer (Feldman/Pedersen) over secret coordinates.
- Oversample (n = t + δ) and choose full-rank subsets.
- Avoid small primes; pick p large enough so invertibility is near 1.
