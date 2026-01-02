# blakley_phase3.py
# Phase 3 experiments for Blakley's secret sharing
# Requires: Python 3.8+, numpy (optional but recommended)
# Usage: import functions from this file or run the examples in __main__.

import random
import math
from itertools import product
from collections import Counter
import numpy as np

# -------------------------
# Modular arithmetic helpers
# -------------------------
def modinv(a, p):
    """Modular inverse assuming p prime and a % p != 0."""
    return pow(a % p, p - 2, p)

def mod_mat_copy(A, p):
    return [[int(x) % p for x in row] for row in A]

# -------------------------
# Modular Gaussian elimination
# -------------------------
def gauss_jordan_mod(A, b=None, p=101):
    """
    Perform Gauss-Jordan elimination on matrix A (list of lists) modulo p.
    If b provided, treat as augmented matrix. Returns:
      rank, reduced_matrix, reduced_b (or None), pivot_cols, row_ops
    Also returns one particular solution if system is consistent (when b given).
    """
    A = mod_mat_copy(A, p)
    m = len(A)
    n = len(A[0]) if m>0 else 0
    if b is None:
        aug = False
        B = [row[:] for row in A]
    else:
        aug = True
        B = [row[:] + [int(bi)%p] for row, bi in zip(A, b)]
    rows = m
    cols = n + (1 if aug else 0)
    r = 0
    pivot_cols = []
    for c in range(n):
        # find pivot row
        sel = None
        for i in range(r, rows):
            if B[i][c] % p != 0:
                sel = i; break
        if sel is None:
            continue
        # swap
        B[r], B[sel] = B[sel], B[r]
        inv = modinv(B[r][c], p)
        # normalize pivot row
        B[r] = [(val * inv) % p for val in B[r]]
        # eliminate others
        for i in range(rows):
            if i == r: continue
            factor = B[i][c] % p
            if factor != 0:
                B[i] = [ (B[i][j] - factor * B[r][j]) % p for j in range(cols) ]
        pivot_cols.append(c)
        r += 1
        if r == rows:
            break
    rank = r
    # If augmented, check consistency
    if aug:
        # rows with all-zero coefficients but non-zero RHS -> inconsistent
        for i in range(rank, rows):
            row_coeffs = B[i][:n]
            rhs = B[i][n] % p
            if all(x % p == 0 for x in row_coeffs) and rhs != 0:
                return rank, B, pivot_cols, False, None  # inconsistent
        # construct one particular solution: set free vars = 0
        x = [0]*n
        for i, c in enumerate(pivot_cols):
            x[c] = B[i][n] % p
        return rank, B, pivot_cols, True, x
    else:
        return rank, B, pivot_cols, True, None

def nullspace_mod(A, p=101):
    """
    Compute a basis for the nullspace of A (mod p).
    Returns list of basis vectors (each length n) such that any null vector is linear comb mod p.
    """
    m = len(A)
    n = len(A[0]) if m>0 else 0
    rank, B, pivots, ok, _ = gauss_jordan_mod(A, None, p)
    piv_set = set(pivots)
    free_cols = [j for j in range(n) if j not in piv_set]
    basis = []
    # For each free variable, set it to 1 and others free to 0, then solve for pivot vars
    for free in free_cols:
        vec = [0]*n
        vec[free] = 1
        # For each pivot row i with pivot column c, value is - (sum of coeffs * free choices)
        for i, c in enumerate(pivots):
            # In reduced row B[i], columns after reduction correspond to identity at pivot c
            s = 0
            for j in free_cols:
                s = (s + B[i][j] * vec[j]) % p
            vec[c] = (-s) % p
        basis.append(vec)
    return basis

# -------------------------
# Share generation & sampling
# -------------------------
def generate_share_for_secret(s, p, t):
    """
    Given secret vector s (length t), sample a random coefficient vector a (length t)
    (avoid zero-vector) and return (a, b = a^T s mod p).
    """
    while True:
        a = [random.randrange(p) for _ in range(t)]
        if any(x % p != 0 for x in a):
            break
    b = sum((ai * si) for ai, si in zip(a, s)) % p
    return a, b

def sample_shares(secret, n, p, t):
    shares = []
    for _ in range(n):
        a, b = generate_share_for_secret(secret, p, t)
        shares.append((a, b))
    return shares

# -------------------------
# Core experiment functions
# -------------------------
def candidate_count_from_shares(shares, ks, p):
    """
    Given shares list of (a,b), and indices ks (list of indices into shares),
    compute number of solutions in F_p^t to A x = b (mod p).
    Returns integer count (0 if inconsistent) = p^{t - rank} if consistent.
    """
    if len(ks) == 0:
        # full space
        t = len(shares[0][0])
        return p ** t
    A = [shares[i][0] for i in ks]
    b = [shares[i][1] for i in ks]
    rank, _, pivots, consistent, _ = gauss_jordan_mod(A, b, p)
    if not consistent:
        return 0
    t = len(shares[0][0])
    return p ** (t - rank)

def simulate_candidate_count(p, t, n_shares, k, trials=200):
    """
    E1: For many trials sample secret and shares, pick k shares and compute candidate count.
    Returns average candidate count and the list of sample counts.
    """
    counts = []
    for _ in range(trials):
        # sample secret uniformly
        s = [random.randrange(p) for _ in range(t)]
        shares = sample_shares(s, n_shares, p, t)
        # choose random k-share subset
        idxs = random.sample(range(n_shares), k) if k>0 else []
        c = candidate_count_from_shares(shares, idxs, p)
        counts.append(c)
    avg = sum(counts) / len(counts)
    return avg, counts

def estimate_mutual_info(p, t, n_shares, k, trials=200):
    """
    E2: Estimate mutual information I(S; shares_k) by sampling.
    H(S) = t * log2 p
    H(S | shares) = E_share [ log2(candidate_count) ] (for uniform S and deterministic mapping)
    So I = H(S) - E[log2(count)].
    """
    sum_log2_counts = 0.0
    zero_inconsistent = 0
    for _ in range(trials):
        s = [random.randrange(p) for _ in range(t)]
        shares = sample_shares(s, n_shares, p, t)
        idxs = random.sample(range(n_shares), k) if k>0 else []
        c = candidate_count_from_shares(shares, idxs, p)
        if c == 0:
            zero_inconsistent += 1
            # treat inconsistent as log2(0) -> large; but for mutual info, inconsistent means dealer produced inconsistent shares wrt secret (shouldn't happen)
            # We skip inconsistent cases (they indicate bad sampling) - rare
            continue
        sum_log2_counts += math.log2(c)
    avg_log2 = sum_log2_counts / (trials - zero_inconsistent) if trials != zero_inconsistent else float('inf')
    H_S = t * math.log2(p)
    H_S_given = avg_log2
    I = H_S - H_S_given
    return {'H_S': H_S, 'H_S_given': H_S_given, 'I_bits': I, 'skipped_inconsistent': zero_inconsistent}

def solve_one_solution_from_shares(shares, ks, p):
    """
    Return one solution vector x (particular) if consistent, else None.
    Uses gauss_jordan_mod to find particular solution with free vars = 0.
    """
    if len(ks) == 0:
        # arbitrary pick zero vector
        t = len(shares[0][0])
        return [0]*t
    A = [shares[i][0] for i in ks]
    b = [shares[i][1] for i in ks]
    rank, _, pivots, consistent, x = gauss_jordan_mod(A, b, p)
    if not consistent:
        return None
    return x  # particular solution

def sample_uniform_solution_from_affine(shares, ks, p, samples=1):
    """
    Given shares and ks, sample uniformly from solution set:
      find particular solution x0 and nullspace basis B = [v1,..,vr].
    Then sample random coefficients in F_p for the nullspace and return x = x0 + sum(ci*vi).
    If inconsistent -> return [].
    """
    if len(ks) == 0:
        t = len(shares[0][0])
        return [[random.randrange(p) for _ in range(t)] for __ in range(samples)]
    A = [shares[i][0] for i in ks]
    b = [shares[i][1] for i in ks]
    rank, _, pivots, consistent, x0 = gauss_jordan_mod(A, b, p)
    if not consistent:
        return []
    t = len(shares[0][0])
    basis = nullspace_mod(A, p)  # basis length = t - rank
    if len(basis) == 0:
        return [x0[:] for _ in range(samples)]
    sols = []
    for _ in range(samples):
        coeffs = [random.randrange(p) for __ in range(len(basis))]
        x = x0[:]
        for ci, v in zip(coeffs, basis):
            for j in range(t):
                x[j] = (x[j] + ci * v[j]) % p
        sols.append([int(xj)%p for xj in x])
    return sols

def attack_best_guess(p, t, n_shares, k, trials=500):
    """
    E3: Adversary picks one particular solution (as best guess) from chosen k shares.
    Measure exact-match success probability (rare), and compare to random guess baseline (1/p^t).
    Returns dict with success_prob, baseline.
    """
    success = 0
    impossible = 0
    for _ in range(trials):
        s = [random.randrange(p) for _ in range(t)]
        shares = sample_shares(s, n_shares, p, t)
        ks = random.sample(range(n_shares), k) if k>0 else []
        x_hat = solve_one_solution_from_shares(shares, ks, p)
        if x_hat is None:
            impossible += 1
            continue
        if [xi % p for xi in x_hat] == [si % p for si in s]:
            success += 1
    eff_trials = trials - impossible
    succ_prob = success / eff_trials if eff_trials>0 else 0.0
    baseline = 1.0 / (p ** t)
    return {'success_prob': succ_prob, 'baseline_random_guess': baseline, 'skipped_inconsistent': impossible}

def rank_failure_rate(p, t, n_shares, trials=1000):
    """
    E5: Probability that a randomly chosen subset of t shares yields rank < t (singular A).
    We sample shares for many secrets and random t-subsets.
    """
    fails = 0
    total = 0
    for _ in range(trials):
        s = [random.randrange(p) for _ in range(t)]
        shares = sample_shares(s, n_shares, p, t)
        idxs = random.sample(range(n_shares), t)
        A = [shares[i][0] for i in idxs]
        rank, _, _, _, _ = gauss_jordan_mod(A, None, p)
        if rank < t:
            fails += 1
        total += 1
    return {'rank_failure_rate': fails / total, 'fails': fails, 'total': total}

def dos_simulation(p, t, n_shares, trials=500, corruption_prob=0.1):
    """
    Simulate DoS by having each share be correct with prob (1-corruption_prob) else random bogus share.
    Reconstruct using a random t-subset and check success.
    Return success fraction.
    """
    successes = 0
    for _ in range(trials):
        s = [random.randrange(p) for _ in range(t)]
        shares = []
        for _ in range(n_shares):
            if random.random() < corruption_prob:
                # bogus share: random a,b (may or may not be consistent)
                a = [random.randrange(p) for _ in range(t)]
                b = random.randrange(p)
            else:
                a,b = generate_share_for_secret(s, p, t)
            shares.append((a,b))
        # try many random subsets until find a consistent reconstruction or declare fail
        recovered = False
        for _ in range(20):
            idxs = random.sample(range(n_shares), t)
            sol = solve_one_solution_from_shares(shares, idxs, p)
            if sol is not None and [x%p for x in sol] == [si%p for si in s]:
                recovered = True
                break
        if recovered:
            successes += 1
    return {'recovery_rate': successes / trials, 'trials': trials, 'corruption_prob': corruption_prob}

def coordinate_posterior_entropy(p, t, n_shares, k, coord_idx=0, trials=200, samples_per_trial=200):
    """
    E4: For a chosen coordinate index, estimate posterior entropy H(s_coord | k shares).
    For each trial:
      - sample secret s and shares
      - pick k shares -> get solution affine subspace
      - sample many uniform solutions from that affine set and record distribution of coordinate
      - compute entropy of that coordinate distribution
    Returns average entropy (bits) across trials and distribution snapshots (optional).
    """
    entropies = []
    for _ in range(trials):
        s = [random.randrange(p) for _ in range(t)]
        shares = sample_shares(s, n_shares, p, t)
        ks = random.sample(range(n_shares), k) if k>0 else []
        sols = sample_uniform_solution_from_affine(shares, ks, p, samples=samples_per_trial)
        if len(sols) == 0:
            continue
        counts = Counter([sol[coord_idx] for sol in sols])
        total = sum(counts.values())
        H = 0.0
        for v in counts.values():
            pprob = v / total
            H -= pprob * math.log2(pprob)
        entropies.append(H)
    avg_H = sum(entropies) / len(entropies) if entropies else None
    return {'avg_entropy_bits': avg_H, 'trials_counted': len(entropies)}

# -------------------------
# Main example
# -------------------------
if __name__ == "__main__":
    random.seed(0)
    np.random.seed(0)

    # quick demo: small p,t to show correctness
    p = 101
    t = 4
    n_shares = t + 3

    print("=== E1: candidate count demo ===")
    avg, counts = simulate_candidate_count(p, t, n_shares, k=1, trials=200)
    print("avg candidate count for k=1:", avg, "theoretical p^(t-1)=", p**(t-1))

    print("\n=== E2: mutual info demo ===")
    mi = estimate_mutual_info(p, t, n_shares, k=1, trials=200)
    print(mi)

    print("\n=== E3: best-guess attack demo ===")
    atk = attack_best_guess(p, t, n_shares, k=1, trials=500)
    print(atk)

    print("\n=== E5: rank failure rate demo ===")
    rf = rank_failure_rate(11, 6, n_shares=8, trials=400)
    print(rf)

    print("\n=== E6: DOS simulation demo ===")
    dos = dos_simulation(101, 4, n_shares=7, trials=400, corruption_prob=0.15)
    print(dos)

    print("\n=== E4: coordinate posterior entropy demo ===")
    coord = coordinate_posterior_entropy(101, 4, n_shares, k=1, coord_idx=0, trials=150, samples_per_trial=300)
    print(coord)
