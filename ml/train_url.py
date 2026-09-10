"""Fishing URL klassifikatorini o'qitish (TZ: FT-23, QM-01…QM-05, QM-12).

Foydalanish:
    python -m ml.train_url --data data/urls.csv --out ml/models/url_phish.joblib

data/urls.csv formati:
    url,label            # label: 1 = phishing, 0 = benign

Skript baseline (TF-IDF + LogisticRegression) va asosiy model (HistGradientBoosting)
ni birga o'qitadi, 5-fold stratifikatsiyalangan CV bilan baholaydi va QM-12
talabini (baseline ustidan F1 bo'yicha ≥ +5 p.p.) tekshiradi.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from urllib.parse import urlparse

import numpy as np

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "n_dots", "n_hyphens", "n_digits_host",
    "digit_ratio_host", "n_subdomains", "host_entropy", "path_entropy",
    "is_ip", "is_punycode", "has_at", "no_tls", "odd_port", "n_params",
    "brand_hit", "brand_weight", "lure_count", "risky_tld", "sld_len",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum(p * math.log2(p) for p in
                (s.count(c) / len(s) for c in set(s)))


def extract(url: str) -> list[float]:
    """URL dan 21 ta leksik/host belgisini ajratadi."""
    from app.detect import brands

    p = urlparse(url if "//" in url else f"http://{url}")
    host = (p.hostname or "").lower()
    path = p.path or ""
    labels = host.split(".") if host else []
    sld = labels[-2] if len(labels) >= 2 else host
    digits = sum(c.isdigit() for c in host)

    m = brands.match_host(host) if host else None
    brand_hit = 1.0 if (m and m.kind != "exact_official") else 0.0
    brand_weight = float(m.weight) if m else 0.0

    risky = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "rest", "site", "online"}

    return [
        len(url), len(host), len(path),
        host.count("."), host.count("-"), digits,
        digits / len(host) if host else 0.0,
        max(0, len(labels) - 2),
        _entropy(host), _entropy(path),
        1.0 if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host or "") else 0.0,
        1.0 if brands.is_punycode(host) else 0.0,
        1.0 if "@" in (p.netloc or "") else 0.0,
        1.0 if p.scheme == "http" else 0.0,
        1.0 if (p.port and p.port not in (80, 443)) else 0.0,
        float((p.query or "").count("&") + (1 if p.query else 0)),
        brand_hit, brand_weight,
        float(len(brands.lure_hits(host + path))),
        1.0 if (labels and labels[-1] in risky) else 0.0,
        float(len(sld)),
    ]


def load(path: Path) -> tuple[list[str], np.ndarray]:
    import csv
    urls, ys = [], []
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            u = (row.get("url") or "").strip()
            if not u:
                continue
            urls.append(u)
            ys.append(int(row["label"]))
    return urls, np.array(ys)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("data/urls.csv"))
    ap.add_argument("--out", type=Path, default=Path("ml/models/url_phish.joblib"))
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    if not args.data.exists():
        print(f"XATO: {args.data} topilmadi. Dataset yig'ilmagan (TZ: QM-18).")
        return 1

    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import StratifiedKFold
    from sklearn.pipeline import make_pipeline

    urls, y = load(args.data)
    if len(set(y)) < 2:
        print("XATO: datasetda ikkala sinf ham bo'lishi kerak.")
        return 1
    X = np.array([extract(u) for u in urls], dtype=float)
    print(f"Dataset: {len(urls)} namuna, phishing ulushi {y.mean():.1%}")

    cv = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=42)
    scores: dict[str, dict[str, list[float]]] = {"baseline": {}, "gbdt": {}}

    for name in scores:
        scores[name] = {k: [] for k in ("precision", "recall", "f1", "auc")}

    for tr, te in cv.split(X, y):
        base = make_pipeline(
            TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=20000),
            LogisticRegression(max_iter=1000, class_weight="balanced"),
        )
        base.fit([urls[i] for i in tr], y[tr])
        pb = base.predict_proba([urls[i] for i in te])[:, 1]

        gbdt = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08,
                                              random_state=42)
        gbdt.fit(X[tr], y[tr])
        pg = gbdt.predict_proba(X[te])[:, 1]

        for key, prob in (("baseline", pb), ("gbdt", pg)):
            pred = (prob >= 0.5).astype(int)
            scores[key]["precision"].append(precision_score(y[te], pred, zero_division=0))
            scores[key]["recall"].append(recall_score(y[te], pred, zero_division=0))
            scores[key]["f1"].append(f1_score(y[te], pred, zero_division=0))
            scores[key]["auc"].append(roc_auc_score(y[te], prob))

    report = {k: {m: round(float(np.mean(v)), 4) for m, v in d.items()}
              for k, d in scores.items()}
    report["f1_gain_pp"] = round((report["gbdt"]["f1"] - report["baseline"]["f1"]) * 100, 2)

    print(json.dumps(report, indent=2))
    _check(report)

    final = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, random_state=42)
    final.fit(X, y)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    import joblib
    joblib.dump({"model": final, "features": FEATURE_NAMES, "report": report}, args.out)
    args.out.with_suffix(".json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Model saqlandi: {args.out}")
    return 0


def _check(r: dict) -> None:
    """TZ 6.1-bandidagi qabul mezonlarini tekshiradi."""
    g = r["gbdt"]
    checks = [
        ("QM-01 precision ≥ 0.93", g["precision"] >= 0.93),
        ("QM-02 recall ≥ 0.90", g["recall"] >= 0.90),
        ("QM-03 f1 ≥ 0.91", g["f1"] >= 0.91),
        ("QM-04 roc_auc ≥ 0.96", g["auc"] >= 0.96),
        ("QM-12 baseline ustidan ≥ +5 p.p.", r["f1_gain_pp"] >= 5.0),
    ]
    print("\nQabul mezonlari:")
    for name, ok in checks:
        print(f"  [{'OK ' if ok else 'YO`Q'}] {name}")


if __name__ == "__main__":
    raise SystemExit(main())
