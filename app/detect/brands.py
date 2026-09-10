"""O'zbekiston moliyaviy brendlari va ularga taqlidni aniqlash.

TZ: FT-01 (CT log filtri), FT-21 (qoidaviy aniqlash), FT-23 (URL belgilari).

Bu modul tizimning milliy kontekstga moslashtirilgan yadrosi: xalqaro
yechimlar mahalliy brendlarga taqlid qiluvchi domenlarni tanimaydi.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# --------------------------------------------------------------- brendlar
# Har bir yozuv: kanonik nom -> rasmiy domenlar
BRANDS: dict[str, set[str]] = {
    # to'lov tizimlari va superilovalar
    "click": {"click.uz"},
    "payme": {"payme.uz"},
    "paynet": {"paynet.uz"},
    "uzum": {"uzum.uz"},
    "apelsin": {"apelsin.uz"},
    "oson": {"oson.uz"},
    # karta tizimlari
    "uzcard": {"uzcard.uz"},
    "humo": {"humo.uz"},
    # banklar
    "nbu": {"nbu.uz"},
    "sqb": {"sqb.uz"},
    "asakabank": {"asakabank.uz"},
    "agrobank": {"agrobank.uz"},
    "xalqbank": {"xb.uz", "xalqbank.uz"},
    "kapitalbank": {"kapitalbank.uz"},
    "ipotekabank": {"ipotekabank.uz"},
    "infinbank": {"infinbank.uz"},
    "anorbank": {"anorbank.uz"},
    "tbcbank": {"tbcbank.uz"},
    "hamkorbank": {"hamkorbank.uz"},
    "ipakyulibank": {"ipakyulibank.uz"},
    "trastbank": {"trastbank.uz"},
    # aloqa operatorlari
    "beeline": {"beeline.uz"},
    "ucell": {"ucell.uz"},
    "uzmobile": {"uzmobile.uz"},
    "mobiuz": {"mobi.uz"},
    # davlat xizmatlari
    "myid": {"myid.uz"},
    "soliq": {"soliq.uz"},
    "mygov": {"my.gov.uz"},
    "davxizmat": {"davxizmat.uz"},
}

OFFICIAL_DOMAINS: set[str] = {d for ds in BRANDS.values() for d in ds}

# Fishing sahifalarida uchraydigan yo'l/subdomen so'zlari
LURE_TOKENS = {
    "login", "signin", "kirish", "verify", "tasdiq", "tasdiqlash", "confirm",
    "secure", "xavfsiz", "update", "yangilash", "account", "hisob", "akkaunt",
    "card", "karta", "payment", "tolov", "bonus", "sovga", "sovrin", "yutuq",
    "promo", "aksiya", "pul", "naqd", "kredit", "id", "auth", "wallet", "hamyon",
}

# --------------------------------------------------------------- homoglif
# Kirill va boshqa yozuvlardagi lotin harflariga o'xshash belgilar
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g", "ᴜ": "u",
    "α": "a", "ο": "o", "ρ": "p", "ϲ": "c", "ν": "v", "μ": "m", "τ": "t",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "9": "g",
}

# Klaviatura qo'shnichiligi (QWERTY) — typosquat generatsiyasi uchun
_ADJACENT = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}


def skeletonize(text: str) -> str:
    """Homoglif va IDN hiylalarini yechib, qiyoslanadigan 'skelet' hosil qiladi."""
    text = unicodedata.normalize("NFKC", text.lower())
    out = []
    for ch in text:
        out.append(HOMOGLYPHS.get(ch, ch))
    s = "".join(out)
    s = re.sub(r"[^a-z0-9]", "", s)
    # takroriy harflarni siqish: clickk -> click, ccclick -> click
    s = re.sub(r"(.)\1{1,}", r"\1", s)
    return s


def decode_idn(host: str) -> str:
    """xn-- ko'rinishidagi qismlarni Unicode ga ochadi (FT-21 homoglif tekshiruvi)."""
    parts = []
    for p in host.lower().split("."):
        if p.startswith("xn--"):
            try:
                parts.append(p.encode("ascii").decode("idna"))
            except Exception:
                parts.append(p)
        else:
            parts.append(p)
    return ".".join(parts)


def lure_hits(host: str) -> list[str]:
    """Hostdagi tuzoq so'zlarni topadi (nuqta/defis bilan ajratilgan yoki ichma-ich)."""
    flat = re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", host.lower()))
    return sorted(t for t in LURE_TOKENS if t in flat)


def has_non_latin(text: str) -> bool:
    """IDN/homoglif hujumining birlamchi alomati."""
    core = re.sub(r"[^\w]", "", text, flags=re.UNICODE)
    return any(ord(c) > 127 for c in core)


def is_punycode(host: str) -> bool:
    return any(part.startswith("xn--") for part in host.lower().split("."))


def levenshtein(a: str, b: str, cutoff: int = 3) -> int:
    """Cheklangan Levenshtein masofasi (cutoff dan katta bo'lsa cutoff+1 qaytaradi)."""
    if abs(len(a) - len(b)) > cutoff:
        return cutoff + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cutoff:
            return cutoff + 1
        prev = cur
    return prev[-1]


def typosquat_variants(brand: str) -> set[str]:
    """Brend nomining tipik buzilgan variantlarini generatsiya qiladi.

    CT log oqimini oldindan filtrlash uchun ishlatiladi (FT-01).
    """
    v: set[str] = set()
    n = len(brand)
    for i in range(n):
        v.add(brand[:i] + brand[i + 1:])                      # tushirib qoldirish
        v.add(brand[:i] + brand[i] * 2 + brand[i + 1:])        # takrorlash
        for c in _ADJACENT.get(brand[i], ""):
            v.add(brand[:i] + c + brand[i + 1:])               # qo'shni harf
    for i in range(n - 1):
        v.add(brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:])  # o'rin almashish
    for i in range(1, n):
        v.add(brand[:i] + "-" + brand[i:])                     # defis qo'shish
    v.discard(brand)
    return {x for x in v if len(x) >= 3}


# --------------------------------------------------------------- natija
@dataclass
class BrandMatch:
    brand: str
    kind: str                 # exact_official | typosquat | homoglyph | subdomain_abuse | keyword
    distance: int = 0
    evidence: list[str] = field(default_factory=list)

    @property
    def weight(self) -> int:
        return {
            "typosquat": 35,
            "homoglyph": 40,
            "subdomain_abuse": 45,
            "keyword": 15,
            "exact_official": 0,
        }[self.kind]


def _registrable(host: str) -> tuple[str, str]:
    """(subdomenlar, ro'yxatga olinadigan qism) — .uz uchun soddalashtirilgan."""
    host = host.lower().strip(".")
    parts = host.split(".")
    multi = {"co.uz", "com.uz", "org.uz", "net.uz", "gov.uz", "ac.uz", "pp.uz"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in multi:
        return ".".join(parts[:-3]), ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return "", host


def match_host(host: str) -> BrandMatch | None:
    """Hostni brendlar reyestriga solishtiradi. Eng og'ir topilmani qaytaradi."""
    raw = host.lower().strip().strip(".")
    if not raw:
        return None

    puny = is_punycode(raw)
    host = decode_idn(raw) if puny else raw

    sub, registrable = _registrable(host)
    if registrable in OFFICIAL_DOMAINS:
        return BrandMatch(_brand_of(registrable), "exact_official")

    sld = registrable.split(".")[0]
    sld_skel = skeletonize(sld)
    sub_skel = skeletonize(sub)

    best: BrandMatch | None = None
    for brand in BRANDS:
        b_skel = skeletonize(brand)
        if not b_skel:
            continue

        # 1) Rasmiy brend subdomenda, ro'yxat qismi begona:
        #    click.uz.tasdiqlash-hisob.com — eng xavfli naqsh
        if b_skel in sub_skel:
            cand = BrandMatch(brand, "subdomain_abuse",
                              evidence=[f"'{brand}' subdomenda: {sub}"])
            if not best or cand.weight > best.weight:
                best = cand
            continue

        # 2) Skelet aynan mos
        if sld_skel == b_skel:
            if puny or has_non_latin(sld):
                cand = BrandMatch(brand, "homoglyph",
                                  evidence=[f"'{sld}' skeleti '{brand}' bilan mos, yozuv lotin emas"])
            else:
                cand = BrandMatch(brand, "typosquat", 0,
                                  [f"'{sld}' rasmiy bo'lmagan domenda '{brand}' ni takrorlaydi"])
            if not best or cand.weight > best.weight:
                best = cand
            continue

        # 3) Brend domen ichida boshqa so'zlar bilan: payme-kirish, click-bonus
        if b_skel in sld_skel:
            kind = "homoglyph" if (puny or has_non_latin(sld)) else "typosquat"
            cand = BrandMatch(brand, kind, len(sld_skel) - len(b_skel),
                              [f"'{brand}' domen nomi ichida: {sld}"])
            if not best or cand.weight > best.weight:
                best = cand
            continue

        # 4) Yaqin masofa
        if abs(len(sld_skel) - len(b_skel)) > 2:
            continue
        d = levenshtein(sld_skel, b_skel, cutoff=2)
        if d <= 2:
            cand = BrandMatch(brand, "typosquat", d,
                              [f"'{sld}' '{brand}' dan {d} belgiga farq qiladi"])
            if not best or cand.weight > best.weight:
                best = cand

    hits = lure_hits(host)
    if best:
        if hits:
            best.evidence.append(f"tuzoq so'zlar: {', '.join(hits)}")
        return best

    # 5) Brend yo'q, lekin tuzoq so'zlar bor
    if hits:
        return BrandMatch("", "keyword", evidence=[f"tuzoq so'zlar: {', '.join(hits)}"])
    return None


def _brand_of(domain: str) -> str:
    for b, ds in BRANDS.items():
        if domain in ds:
            return b
    return ""


def ct_log_prefilter() -> set[str]:
    """CT log oqimini filtrlash uchun kalit so'zlar to'plami (FT-01)."""
    keys: set[str] = set()
    for brand in BRANDS:
        keys.add(brand)
        keys |= typosquat_variants(brand)
    return keys
