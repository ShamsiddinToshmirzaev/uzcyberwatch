"""Gibrid aniqlash yadrosi.

TZ: FT-21 … FT-28. Qoidaviy, ML va evristik qatlamlar natijasini
birlashtirib, hodisaga 0–100 risk-ball va sabablar ro'yxatini beradi.

Muhim: sabablar ro'yxati (explainability) majburiy — analitik nima uchun
ogohlantirish chiqqanini ko'rmasa, tizimga ishonmaydi va FPR amalda
100% bo'lib qoladi.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

from app.detect import brands, text_rules, legal_map
from app.normalize import lang, pii


@dataclass
class Reason:
    layer: str          # rule | ml | heuristic | enrichment
    code: str
    weight: int
    detail: str


@dataclass
class Verdict:
    risk_score: int
    incident_type: str
    confidence: float
    reasons: list[Reason] = field(default_factory=list)
    legal: list[dict] = field(default_factory=list)
    pii_found: list[dict] = field(default_factory=list)
    lang: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["reasons"] = [asdict(r) for r in self.reasons]
        return d


# Kombinatsiya: og'irliklar mustaqil ehtimolliklar kabi birlashtiriladi,
# ya'ni bitta kuchli signal ballni 100 ga olib chiqmaydi.
def _combine(weights: list[int]) -> int:
    if not weights:
        return 0
    prob_clean = 1.0
    for w in weights:
        prob_clean *= (1 - min(max(w, 0), 95) / 100)
    return int(round((1 - prob_clean) * 100))


def analyse(
    url: str | None = None,
    text: str | None = None,
    domain_age_days: int | None = None,
    ml_score: float | None = None,
    has_payload: bool = False,
) -> Verdict:
    reasons: list[Reason] = []
    detected_lang = None
    text_rule_names: list[str] = []
    brand_kind = None

    # ---------------------------------------------------- URL / domen qatlami
    host = None
    if url:
        parsed = urlparse(url if "//" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()

        m = brands.match_host(host)
        if m and m.kind != "exact_official":
            brand_kind = m.kind
            reasons.append(Reason("rule", f"brand_{m.kind}", m.weight,
                                  "; ".join(m.evidence) or m.kind))

        for code, w, detail in _url_heuristics(parsed, host):
            reasons.append(Reason("heuristic", code, w, detail))

    # ---------------------------------------------------- domen yoshi (FT-16)
    if domain_age_days is not None:
        if domain_age_days <= 7:
            reasons.append(Reason("enrichment", "domain_very_fresh", 30,
                                  f"domen {domain_age_days} kun oldin ro'yxatdan o'tgan"))
        elif domain_age_days <= 30:
            reasons.append(Reason("enrichment", "domain_fresh", 18,
                                  f"domen {domain_age_days} kunlik"))

    # ---------------------------------------------------- matn qatlami
    pii_hits: list[pii.PiiHit] = []
    if text:
        detected_lang, norm = lang.normalize_text(text)
        for h in text_rules.scan_text(norm):
            text_rule_names.append(h.rule)
            reasons.append(Reason("rule", f"text_{h.rule}", h.weight,
                                  f"{h.description}: «{h.snippet}»"))
        pii_hits = pii.scan(text)
        if any(h.kind == "card" for h in pii_hits):
            reasons.append(Reason("rule", "text_contains_pan", 25,
                                  "matnda haqiqiy karta raqami mavjud"))

    # ---------------------------------------------------- ML qatlami (FT-23)
    if ml_score is not None:
        w = int(round(ml_score * 60))          # modelga maksimal 60 og'irlik
        if w >= 12:
            reasons.append(Reason("ml", "url_phish_gbdt", w,
                                  f"model ehtimolligi {ml_score:.2f}"))

    # ---------------------------------------------------- yig'ish
    risk = _combine([r.weight for r in reasons])
    incident = legal_map.classify_incident(brand_kind, text_rule_names, has_payload)
    legal = [
        {"article_code": s.article_code, "confidence": s.confidence,
         "rationale": s.rationale, "requires_review": s.requires_review}
        for s in legal_map.suggest(incident, risk)
    ]

    # ishonch: signallar soni va xilma-xilligiga bog'liq
    layers = {r.layer for r in reasons}
    confidence = round(min(0.99, 0.35 + 0.15 * len(layers) + 0.03 * len(reasons)), 2) if reasons else 0.0

    return Verdict(
        risk_score=risk,
        incident_type=incident,
        confidence=confidence,
        reasons=sorted(reasons, key=lambda r: -r.weight),
        legal=legal,
        pii_found=[{"kind": h.kind, "hint": h.hint, "hash": h.hash} for h in pii_hits],
        lang=detected_lang,
    )


def _url_heuristics(parsed, host: str) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    if not host:
        return out

    labels = host.split(".")
    if len(labels) >= 5:
        out.append(("deep_subdomain", 18, f"{len(labels)} darajali subdomen: {host}"))

    if brands.is_punycode(host):
        out.append(("punycode", 25, f"punycode domen: {host} -> {brands.decode_idn(host)}"))

    if _is_ip(host):
        out.append(("ip_host", 30, "domen o'rniga IP-manzil ishlatilgan"))

    if parsed.port and parsed.port not in (80, 443):
        out.append(("odd_port", 12, f"nostandart port: {parsed.port}"))

    if parsed.scheme == "http":
        out.append(("no_tls", 8, "HTTPS ishlatilmagan"))

    if "@" in (parsed.netloc or ""):
        out.append(("at_in_netloc", 28, "URL da @ belgisi — haqiqiy host yashirilgan"))

    sld = labels[-2] if len(labels) >= 2 else host
    ent = _entropy(sld)
    if ent > 3.6 and len(sld) >= 10:
        out.append(("high_entropy", 20, f"tasodifiy ko'rinishli domen (entropiya {ent:.2f})"))

    digits = sum(c.isdigit() for c in sld)
    if len(sld) and digits / len(sld) > 0.35:
        out.append(("digit_heavy", 14, "domen nomida raqamlar ko'p"))

    if sld.count("-") >= 3:
        out.append(("many_hyphens", 14, f"domen nomida {sld.count('-')} ta defis"))

    tld = labels[-1] if labels else ""
    if tld in {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "rest", "site", "online"}:
        out.append(("risky_tld", 16, f"yuqori xavfli TLD: .{tld}"))

    return out


def _is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())
