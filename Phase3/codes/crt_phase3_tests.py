# crt_phase3_tests.py
# Security analysis & weakness evaluation for Asmuth–Bloom (CRT-based) secret sharing
# Python 3.10+; standard library only

import random
import math
import itertools
import csv
from collections import Counter
from typing import List, Tuple, Dict, Optional

# ---------------------------
# Basic number theory helpers
# ---------------------------

def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_mod(a: int, m: int) -> Optional[int]:
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m

def crt_pair(r1: int, m1: int, r2: int, m2: int) -> Tuple[int,int]:
    """Combine x ≡ r1 (mod m1), x ≡ r2 (mod m2) -> (r, m1*m2). Assumes coprime moduli."""
    g, s, t = egcd(m1, m2)
    assert g == 1
    r = (r1 + (r2 - r1) * s % m2 * m1) % (m1 * m2)
    return (r, m1 * m2)

def crt_list(residues: List[int], moduli: List[int]) -> Tuple[int,int]:
    r, m = residues[0] % moduli[0], moduli[0]
    for i in range(1, len(moduli)):
        r, m = crt_pair(r, m, residues[i] % moduli[i], moduli[i])
    return (r, m)

# ---------------------------
# Asmuth–Bloom core
# ---------------------------

def check_asmuth_bloom_inequality(m0: int, moduli: List[int], t: int) -> bool:
    """Given m0 and increasing moduli m1..mn, check m0 * prod(m_{n-t+2..n}) < prod(m_{1..t})."""
    n = len(moduli) - 1  # moduli[0] is m0 for convenience if passed that way
    m = moduli  # assume m[0]=m0, m[1..n]
    left = m0
    for i in range(n - t + 2, n + 1):
        left *= m[i]
    right = 1
    for i in range(1, t + 1):
        right *= m[i]
    return left < right

def encode_share_set(secret: int, m0: int, moduli: List[int], t: int, alpha: Optional[int]=None) -> Tuple[int,List[Tuple[int,int]]]:
    """
    Asmuth–Bloom encoding.
    moduli: [m0, m1, ..., mn] (pairwise coprime, strictly increasing)
    s' = s + alpha*m0 where alpha chosen so 0 <= s' < prod_{i=1..t} mi
    Returns (s_prime, shares[(mi, ri)])
    """
    Mt = 1
    for i in range(1, t + 1):
        Mt *= moduli[i]
    if alpha is None:
        # choose alpha so s' < Mt
        alpha = random.randrange(0, max(1, (Mt - secret + m0 - 1) // m0))
    s_prime = secret + alpha * m0
    assert 0 <= s_prime < Mt, "alpha choice invalid: s' must be < product of first t moduli"
    shares = []
    for i in range(1, len(moduli)):
        mi = moduli[i]
        ri = s_prime % mi
        shares.append((mi, ri))
    return s_prime, shares

def reconstruct_secret_from_subset(subset: List[Tuple[int,int]], m0: int) -> int:
    """Reconstruct using a subset of t shares: returns S = X mod m0."""
    residues = [r for (_, r) in subset]
    moduli = [m for (m, _) in subset]
    X, M = crt_list(residues, moduli)
    return X % m0

# ---------------------------
# Moduli generation utilities
# ---------------------------

def next_prime(n: int) -> int:
    def is_prime(x: int) -> bool:
        if x < 2: return False
        if x % 2 == 0: return x == 2
        r = int(x**0.5)
        f = 3
        while f <= r:
            if x % f == 0:
                return False
            f += 2
        return True
    x = max(2, n + 1)
    while not is_prime(x):
        x += 1
    return x

def ascending_coprime_moduli(m0: int, n: int, start: int = 5) -> List[int]:
    """
    Return [m0, m1..mn] pairwise coprime primes, increasing.
    start: lower bound for m1
    """
    m = [m0]
    cur = max(start, m0 + 1)
    while len(m) <= n:
        p = next_prime(cur)
        if math.gcd(p, m0) == 1 and all(math.gcd(p, mi) == 1 for mi in m):
            m.append(p)
        cur = p + 1
    return m

def moduli_with_margin(m0: int, t: int, n: int, margin_factor: float = 4.0) -> List[int]:
    """
    Build [m0, m1..mn] such that the AB inequality holds with a controllable multiplicative margin.
    Larger margin_factor -> stronger separation -> safer secrecy.
    """
    # Seed with increasing primes; then scale early moduli up until margin reached
    m = ascending_coprime_moduli(m0, n, start=max(5, m0 + 2))
    # Increase early moduli (m1..mt) until RHS >= margin * LHS
    def lhs_rhs(vals):
        mlist = vals
        left = m0
        for i in range(n - t + 2, n + 1):
            left *= mlist[i]
        right = 1
        for i in range(1, t + 1):
            right *= mlist[i]
        return left, right
    left, right = lhs_rhs(m)
    while right < margin_factor * left:
        # scale earliest moduli by moving to next prime
        for i in range(1, t + 1):
            m[i] = next_prime(m[i] + 1)
        left, right = lhs_rhs(m)
    return m

def moduli_violate_by_factor(m0: int, t: int, n: int, violation_factor: float = 1.1) -> List[int]:
    """
    Build [m0, m1..mn] that violate the AB inequality by a factor >= violation_factor:
    m0 * prod(m_{n-t+2..n}) >= violation_factor * prod(m_{1..t})
    Useful to demonstrate leakage with t-1 shares.
    """
    m = ascending_coprime_moduli(m0, n, start=max(3, m0 + 2))
    # shrink early moduli, enlarge late moduli until violation achieved
    def ratio(vals):
        mlist = vals
        left = m0
        for i in range(n - t + 2, n + 1):
            left *= mlist[i]
        right = 1
        for i in range(1, t + 1):
            right *= mlist[i]
        return left / right
    r = ratio(m)
    # Increase tail moduli and/or decrease head moduli to cross threshold
    while r < violation_factor:
        # bump the last t-1 moduli upward to enlarge LHS
        for i in range(n - t + 2, n + 1):
            m[i] = next_prime(m[i] + random.randint(1, 5))
        # slightly reduce head moduli if possible (keep increasing but constrained)
        for i in range(1, t + 1):
            if m[i] > 5:
                m[i] = max(3, m[i] - 1)  # not necessarily prime; fix back to prime
                if m[i] < 3: m[i] = 3
                if m[i] % 2 == 0: m[i] += 1
                while not all(m[i] % p for p in range(3, int(m[i]**0.5)+1, 2)):
                    m[i] += 2
        r = ratio(m)
    return m

# ---------------------------
# Phase-3 Security Experiments
# ---------------------------

def test_partial_uniformity(m0: int, t: int, n: int, trials: int = 2000, k: int = 2) -> Dict:
    """
    Below-threshold secrecy test: distribution of reconstructed values modulo prod of k moduli
    should be uniform and independent of the true secret (when inequality holds).
    Returns chi-square statistic and p-approx via entropy proxy.
    """
    assert 1 <= k < t
    moduli = moduli_with_margin(m0, t, n, margin_factor=4.0)
    # pick the smallest k moduli for stronger observable support
    m_k = [moduli[i] for i in range(1, k + 1)]
    M_k = math.prod(m_k)

    buckets = Counter()
    for _ in range(trials):
        s = random.randrange(0, m0)
        s_prime, shares = encode_share_set(s, m0, moduli, t)
        # take residues modulo chosen k moduli and CRT them
        residues = [ri for (mi, ri) in shares[:k]]
        xk, _ = crt_list(residues, m_k)
        buckets[xk] += 1

    # Chi-square against uniform
    expected = trials / M_k
    chisq = sum(((cnt - expected) ** 2) / expected for cnt in buckets.values())
    # entropy proxy
    total = sum(buckets.values())
    H = -sum((c/total) * math.log2(c/total) for c in buckets.values())
    return {
        "inequality_ok": check_asmuth_bloom_inequality(m0, moduli, t),
        "M_k": M_k,
        "unique_bins": len(buckets),
        "chisq": chisq,
        "entropy_bits": H,
        "entropy_uniform_bits": math.log2(M_k)
    }

def test_inequality_violation_leakage(m0: int, t: int, n: int, trials: int = 800, k: Optional[int] = None, violation_factor: float = 1.05) -> Dict:
    """
    Construct moduli that violate AB inequality, then test whether k = t-1 shares correlate with the secret mod m0.
    Metric: success rate that reconstructed S_hat (from k shares) equals true S modulo m0
    (should be ~1/m0 when OK; rises significantly when violated).
    """
    if k is None: k = t - 1
    assert 1 <= k < t
    moduli = moduli_violate_by_factor(m0, t, n, violation_factor=violation_factor)

    hits = 0
    for _ in range(trials):
        s = random.randrange(0, m0)
        s_prime, shares = encode_share_set(s, m0, moduli, t)
        # pick k shares (use the largest k to bias towards violation leakage)
        subset = shares[-k:]
        S_hat = reconstruct_secret_from_subset(subset, m0)
        if S_hat == s:
            hits += 1
    baseline = 1.0 / m0
    return {
        "inequality_ok": check_asmuth_bloom_inequality(m0, moduli, t),
        "hit_rate": hits / trials,
        "baseline": baseline,
        "moduli": moduli
    }

def test_redundancy_vs_loss(m0: int, t: int, n: int, loss_fracs: List[float], trials: int = 1000) -> List[Dict]:
    """
    Availability curve: randomly drop shares; success if >= t valid shares remain.
    """
    moduli = moduli_with_margin(m0, t, n, margin_factor=4.0)
    out = []
    for loss in loss_fracs:
        succ = 0
        for _ in range(trials):
            s = random.randrange(0, m0)
            _, shares = encode_share_set(s, m0, moduli, t)
            kept = [sh for sh in shares if random.random() > loss]
            if len(kept) < t:
                continue
            subset = random.sample(kept, t)
            Shat = reconstruct_secret_from_subset(subset, m0)
            if Shat == s:
                succ += 1
        total_trials = trials
        out.append({"loss_frac": loss, "success_rate": succ / total_trials})
    return out

def test_corruption_effect(m0: int, t: int, n: int, corr_prob: float = 0.1, trials: int = 1000) -> Dict:
    """
    Non-verifiability DoS test: each share independently corrupted with prob corr_prob.
    Attempt single-shot reconstruction from random t-subset.
    Record rates: exact, wrong, no_reconstruct (should not happen under CRT).
    """
    moduli = moduli_with_margin(m0, t, n, margin_factor=4.0)
    exact = wrong = fail = 0
    for _ in range(trials):
        s = random.randrange(0, m0)
        _, shares = encode_share_set(s, m0, moduli, t)
        # corrupt some residues
        corr_shares = []
        for (mi, ri) in shares:
            if random.random() < corr_prob:
                ri = random.randrange(0, mi)  # arbitrary residue
            corr_shares.append((mi, ri))
        subset = random.sample(corr_shares, t)
        try:
            Shat = reconstruct_secret_from_subset(subset, m0)
            if Shat == s:
                exact += 1
            else:
                wrong += 1
        except Exception:
            fail += 1
    return {
        "corr_prob": corr_prob,
        "exact_rate": exact / trials,
        "wrong_rate": wrong / trials,
        "fail_rate": fail / trials
    }

def test_malicious_dealer_inconsistency(m0: int, t: int, n: int, trials: int = 1000) -> Dict:
    """
    Dealer gives shares that don't originate from a single s' (two different secrets to disjoint subsets).
    Metric: fraction of random t-subsets that reconstruct different secrets across runs (non-determinism / inconsistency).
    """
    moduli = moduli_with_margin(m0, t, n, margin_factor=4.0)
    inconsistent_rate_acc = 0
    for _ in range(trials):
        # create two different encoded s' for two halves
        sA = random.randrange(0, m0)
        sB = (sA + 1) % m0
        _, sharesA = encode_share_set(sA, m0, moduli, t)
        _, sharesB = encode_share_set(sB, m0, moduli, t)
        # interleave to form a single "global" share set without verifiability
        mixed = []
        for i in range(len(sharesA)):
            mixed.append(sharesA[i] if i % 2 == 0 else sharesB[i])
        # pick two random t-subsets and compare reconstructions
        subset1 = random.sample(mixed, t)
        subset2 = random.sample(mixed, t)
        S1 = reconstruct_secret_from_subset(subset1, m0)
        S2 = reconstruct_secret_from_subset(subset2, m0)
        if S1 != S2:
            inconsistent_rate_acc += 1
    return {
        "inconsistent_fraction": inconsistent_rate_acc / trials,
        "note": "Non-zero indicates undetectable dealer misbehavior without VSS."
    }

def test_noise_sensitivity(m0: int, t: int, n: int, max_noise: int = 20, trials: int = 800) -> List[Dict]:
    """
    Add additive noise delta in [-d, d] to exactly one share in a chosen t-subset and measure success rate.
    Should drop sharply even for small d.
    """
    moduli = moduli_with_margin(m0, t, n, margin_factor=4.0)
    out = []
    for d in range(0, max_noise + 1):
        ok = 0
        for _ in range(trials):
            s = random.randrange(0, m0)
            _, shares = encode_share_set(s, m0, moduli, t)
            subset = random.sample(shares, t)
            j = random.randrange(0, t)
            mi, ri = subset[j]
            delta = random.randint(-d, d) if d > 0 else 0
            ri = (ri + delta) % mi
            subset[j] = (mi, ri)
            Shat = reconstruct_secret_from_subset(subset, m0)
            if Shat == s:
                ok += 1
        out.append({"noise_bound": d, "success_rate": ok / trials})
    return out

def test_candidate_count_below_threshold(m0: int, t: int, n: int, k: int, trials: int = 400) -> Dict:
    """
    For k < t, count number of secrets in Z_{m0} consistent with k residues.
    Under valid AB parameters: count should equal m0 (no reduction).
    Under violated params: count may drop (information leak).
    """
    assert 1 <= k < t
    # Build both safe and violated moduli
    mod_safe = moduli_with_margin(m0, t, n, margin_factor=4.0)
    mod_bad = moduli_violate_by_factor(m0, t, n, violation_factor=1.05)

    def candidate_count(moduli) -> float:
        # fix a subset of k moduli (use largest k)
        sub_mod = moduli[-k:]
        Mk = math.prod(sub_mod)
        total = 0
        for _ in range(trials):
            s = random.randrange(0, m0)
            s_prime, shares = encode_share_set(s, m0, moduli, t)
            residues = [r for (m, r) in shares[-k:]]
            # Count number of s0 in [0, m0-1] s.t. ∃ alpha with s0 + alpha*m0 ≡ residues (mod sub_mod via CRT)
            # Solve for X ≡ residues (mod Mk), then count solutions to X ≡ s0 (mod m0): #solutions = gcd(m0, Mk) (usually 1).
            X, _ = crt_list(residues, sub_mod)
            # solutions for s0: s0 ≡ X (mod gcd(m0, Mk))
            g = math.gcd(m0, Mk)
            # If AB inequality holds, X is random in [0,Mk), but the count of s0 consistent is exactly m0/g.
            total += (m0 // g)
        return total / trials

    cnt_safe = candidate_count(mod_safe)
    cnt_bad = candidate_count(mod_bad)
    return {
        "inequality_ok": check_asmuth_bloom_inequality(m0, mod_safe, t),
        "inequality_bad": check_asmuth_bloom_inequality(m0, mod_bad, t),
        "avg_candidates_safe": cnt_safe,
        "avg_candidates_violated": cnt_bad,
        "theory_safe": m0  # expected candidates under perfect secrecy
    }

# ---------------------------
# Optional CSV dump helpers
# ---------------------------

def write_csv(path: str, header: List[str], rows: List[Dict]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow([r[h] for h in header])

# ---------------------------
# Quick demo (edit as needed)
# ---------------------------

if __name__ == "__main__":
    random.seed(0)

    m0, t, n = 101, 5, 7  # base modulus, threshold, total shares

    print("=== Partial uniformity (k=2) ===")
    u = test_partial_uniformity(m0, t, n, trials=2000, k=2)
    print(u)

    print("\n=== Inequality violation leakage (k=t-1) ===")
    leak = test_inequality_violation_leakage(m0, t, n, trials=1000, violation_factor=1.05)
    print(leak)

    print("\n=== Redundancy vs loss ===")
    loss_curve = test_redundancy_vs_loss(m0, t, n, loss_fracs=[0.0,0.1,0.2,0.3,0.4,0.5,0.6], trials=800)
    for row in loss_curve: print(row)

    print("\n=== Corruption effect (non-verifiability) ===")
    corr = test_corruption_effect(m0, t, n, corr_prob=0.15, trials=1000)
    print(corr)

    print("\n=== Malicious dealer inconsistency ===")
    inc = test_malicious_dealer_inconsistency(m0, t, n, trials=600)
    print(inc)

    print("\n=== Noise sensitivity ===")
    ns = test_noise_sensitivity(m0, t, n, max_noise=10, trials=600)
    for row in ns: print(row)

    print("\n=== Candidate count below threshold (k= t-1) ===")
    cc = test_candidate_count_below_threshold(m0, t, n, k=t-1, trials=600)
    print(cc)
