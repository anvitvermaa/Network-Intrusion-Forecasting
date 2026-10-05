

#!/usr/bin/env python3

"""Trivial baselines + forecastability diagnostics for kill-chain stage forecasting.

 

Dataset-agnostic. Input: lists of stage sequences (one list per attack episode),

already split into train and test. Every method answers the same question:

given the true stage at time t, what is the stage at time t+k?

 

Methods

  persistence   : next = current ("tomorrow is like today")

  advance_one   : next = following stage in kill-chain order (capped at the last)

  majority_next : the single most common next stage in training, whatever the current stage

  markov1       : most frequent next stage given the current one, counted on training data

  learned       : any transition matrix you pass in (e.g. the project's HMM)

 

Diagnostics

  distinct_transitions : how many different (a -> b, a != b) stage changes occur

  cond_entropy_bits    : H(next | current), how unpredictable the next stage is

  ceiling_first_order  : best accuracy ANY rule using only the current stage could get on this data

  fano_bound           : information-theoretic upper bound on accuracy from the entropy

"""

import math

import numpy as np

 

 

def _pairs(seqs, k=1):

    out = []

    for s in seqs:

        for t in range(len(s) - k):

            out.append((s[t], s[t + k], s[t + 1] != s[t]))

    return out

 

 

def transition_counts(seqs, stages):

    idx = {s: i for i, s in enumerate(stages)}

    C = np.zeros((len(stages), len(stages)))

    for a, b, _ in _pairs(seqs, 1):

        C[idx[a], idx[b]] += 1

    return C

 

 

def row_normalise(C, alpha=0.0):

    C = C + alpha

    rs = C.sum(axis=1, keepdims=True)

    rs[rs == 0] = 1.0

    return C / rs

 

 

def kstep_predictor_from_matrix(P, stages, k, fallback=None):

    idx = {s: i for i, s in enumerate(stages)}

    Pk = np.linalg.matrix_power(P, k)

 

    def f(cur):

        row = Pk[idx[cur]]

        if row.sum() == 0 and fallback is not None:

            return fallback(cur)

        return stages[int(np.argmax(row))]

    return f

 

 

def make_methods(train_seqs, stages, order, k=1, learned_P=None):

    """order: the kill-chain order used by advance_one (list of stages, earliest first)."""

    pos = {s: i for i, s in enumerate(order)}

 

    def advance(cur):

        if cur not in pos:

            return cur

        return order[min(pos[cur] + k, len(order) - 1)]

 

    nxt = [b for a, b, _ in _pairs(train_seqs, k)]

    majority = max(sorted(set(nxt)), key=nxt.count) if nxt else stages[0]  # sorted: deterministic tie-breaking

 

    C = transition_counts(train_seqs, stages)

    P_markov = row_normalise(C, alpha=0.0)

    for i, s in enumerate(stages):  # unseen rows fall back to advance-one

        if C[i].sum() == 0:

            P_markov[i] = 0.0

            P_markov[i, stages.index(advance_one_step(s, order))] = 1.0

 

    methods = {

        "persistence": lambda cur: cur,

        "advance_one": advance,

        "majority_next": lambda cur: majority,

        "markov1": kstep_predictor_from_matrix(P_markov, stages, k),

    }

    if learned_P is not None:

        methods["learned"] = kstep_predictor_from_matrix(np.asarray(learned_P), stages, k)

    return methods

 

 

def advance_one_step(s, order):

    if s not in order:

        return s

    i = order.index(s)

    return order[min(i + 1, len(order) - 1)]

 

 

def _bootstrap_ci(hits_by_episode, n_boot=2000, seed=0):

    rng = np.random.default_rng(seed)

    eps = [h for h in hits_by_episode if len(h)]

    if not eps:

        return [None, None]

    accs = []

    for _ in range(n_boot):

        pick = rng.integers(0, len(eps), len(eps))

        allh = np.concatenate([eps[i] for i in pick])

        accs.append(allh.mean())

    return [float(np.percentile(accs, 2.5)), float(np.percentile(accs, 97.5))]

 

 

def evaluate(methods, test_seqs, k=1, n_boot=2000):

    """Accuracy at every step, and only at real stage changes (where the stage actually moves)."""

    res = {}

    for name, f in methods.items():

        all_ep, chg_ep = [], []

        for s in test_seqs:

            h_all, h_chg = [], []

            for t in range(len(s) - k):

                hit = f(s[t]) == s[t + k]

                h_all.append(hit)

                if s[t + 1] != s[t]:

                    h_chg.append(hit)

            all_ep.append(np.array(h_all, dtype=float))

            chg_ep.append(np.array(h_chg, dtype=float))

        a = np.concatenate(all_ep) if any(len(x) for x in all_ep) else np.array([])

        c = np.concatenate(chg_ep) if any(len(x) for x in chg_ep) else np.array([])

        res[name] = {

            "acc_all": float(a.mean()) if len(a) else None, "n_all": int(len(a)),

            "acc_all_ci95": _bootstrap_ci(all_ep, n_boot),

            "acc_changes": float(c.mean()) if len(c) else None, "n_changes": int(len(c)),

            "acc_changes_ci95": _bootstrap_ci(chg_ep, n_boot),

        }

    return res

 

 

def paired_difference(methods, a, b, test_seqs, k=1, n_boot=2000, seed=0):

    """Bootstrap CI (over episodes) of accuracy(a) - accuracy(b). If it excludes 0, the gap is real."""

    rng = np.random.default_rng(seed)

    diffs = []

    for s in test_seqs:

        d = [float(methods[a](s[t]) == s[t + k]) - float(methods[b](s[t]) == s[t + k]) for t in range(len(s) - k)]

        if d:

            diffs.append(np.array(d))

    if not diffs:

        return {"mean_diff": None, "ci95": [None, None]}

    mean = float(np.concatenate(diffs).mean())

    boots = []

    for _ in range(n_boot):

        pick = rng.integers(0, len(diffs), len(diffs))

        boots.append(np.concatenate([diffs[i] for i in pick]).mean())

    return {"mean_diff": mean, "ci95": [float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))]}

 

 

def exact_ci(k, n, alpha=0.05):
    """Clopper-Pearson exact binomial interval; valid at 0/n and n/n, unlike the bootstrap."""
    from scipy.stats import beta
    if n == 0:
        return [None, None]
    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return [lo, hi]


def _h(p):

    return 0.0 if p <= 0 or p >= 1 else -(p * math.log2(p) + (1 - p) * math.log2(1 - p))

 

 

def fano_bound(H, n_states):

    """Largest accuracy pi with  h(pi) + (1 - pi) * log2(n - 1) >= H  (Fano's inequality)."""

    if n_states < 2:

        return 1.0

    lo, hi = 1.0 / n_states, 1.0

    for _ in range(100):

        mid = (lo + hi) / 2

        if _h(mid) + (1 - mid) * math.log2(n_states - 1) >= H:

            lo = mid

        else:

            hi = mid

    return lo

 

 

def diagnostics(seqs, stages, k=1):

    """How forecastable is this set of sequences at all?"""

    pairs = _pairs(seqs, k)

    n = len(pairs)

    if n == 0:

        return {"n_pairs": 0}

    idx = {s: i for i, s in enumerate(stages)}

    C = np.zeros((len(stages), len(stages)))

    for a, b, _ in pairs:

        C[idx[a], idx[b]] += 1

    distinct = int(sum(1 for i in range(len(stages)) for j in range(len(stages)) if i != j and C[i, j] > 0))

    H = 0.0

    for i in range(len(stages)):

        r = C[i].sum()

        if r == 0:

            continue

        p = C[i] / r

        p = p[p > 0]

        H += (r / n) * float(-(p * np.log2(p)).sum())

    ceiling = float(C.max(axis=1).sum() / n)

    n_changes = int(sum(1 for _, _, ch in pairs if ch))

    observed_states = int(((C.sum(axis=1) + C.sum(axis=0)) > 0).sum())

    return {

        "n_episodes": len(seqs), "n_pairs": n, "n_stage_changes": n_changes,

        "share_changes": n_changes / n,

        "distinct_transitions": distinct, "observed_states": observed_states,

        "cond_entropy_bits": float(H),

        "ceiling_first_order": ceiling,

        "fano_bound": fano_bound(H, max(observed_states, 2)),

        "transition_counts": C.astype(int).tolist(),

    }

 

 

def collapse_runs(seq):

    """A A B B B C -> A B C  (keep only stage changes)."""

    out = []

    for s in seq:

        if not out or out[-1] != s:

            out.append(s)

    return out



