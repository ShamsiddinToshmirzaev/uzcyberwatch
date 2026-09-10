"""Til aniqlash va o'zbek kiril/lotin transliteratsiyasi.

TZ: FT-12. Firibgarlik matnlari ikkala yozuvda ham keladi, model esa bitta
yozuvda o'qitiladi — shuning uchun normalizatsiya bosqichida lotinga keltiriladi.
"""
from __future__ import annotations

import re

# ------------------------------------------------------------ transliteratsiya
_CYR2LAT = [
    ("ў", "o'"), ("қ", "q"), ("ғ", "g'"), ("ҳ", "h"),
    ("ч", "ch"), ("ш", "sh"), ("ё", "yo"), ("ю", "yu"), ("я", "ya"),
    ("ж", "j"), ("ц", "s"), ("щ", "sh"), ("ъ", "'"), ("ь", ""),
    ("а", "a"), ("б", "b"), ("в", "v"), ("г", "g"), ("д", "d"),
    ("е", "e"), ("з", "z"), ("и", "i"), ("й", "y"), ("к", "k"),
    ("л", "l"), ("м", "m"), ("н", "n"), ("о", "o"), ("п", "p"),
    ("р", "r"), ("с", "s"), ("т", "t"), ("у", "u"), ("ф", "f"),
    ("х", "x"), ("ы", "i"), ("э", "e"),
]

# O'zbek lotin yozuviga xos belgilar
_UZ_LATIN_MARKERS = ("o'", "g'", "oʻ", "gʻ", "sh", "ch", "ng")
# O'zbek kiril yozuviga xos, rus tilida yo'q harflar
_UZ_CYRL_ONLY = set("ўқғҳ")
# Rus tiliga xos, o'zbek kirilida deyarli uchramaydigan harflar
_RU_ONLY = set("ыэъьщц")


def transliterate(text: str) -> str:
    """O'zbek kirilini lotinga o'giradi. Lotin matn o'zgarishsiz qaytadi."""
    out = text
    for cyr, lat in _CYR2LAT:
        out = out.replace(cyr, lat).replace(cyr.upper(), lat.upper() if len(lat) == 1 else lat.capitalize())
    return out


def normalize_apostrophes(text: str) -> str:
    """oʻ, o', o`, o‘ -> o' (belgilar xilma-xilligi model uchun shovqin)."""
    return re.sub(r"[\u2018\u2019\u02bb\u02bc\u0060\u00b4]", "'", text)


def detect_lang(text: str) -> str:
    """uz-Latn | uz-Cyrl | ru | en | mixed | unknown"""
    t = normalize_apostrophes(text.lower())
    letters = [c for c in t if c.isalpha()]
    if not letters:
        return "unknown"

    cyr = sum(1 for c in letters if "\u0400" <= c <= "\u04ff")
    lat = sum(1 for c in letters if "a" <= c <= "z")
    cyr_ratio = cyr / len(letters)
    lat_ratio = lat / len(letters)

    if cyr_ratio > 0.15 and lat_ratio > 0.15:
        return "mixed"

    if cyr_ratio >= 0.5:
        chars = set(t)
        if chars & _UZ_CYRL_ONLY:
            return "uz-Cyrl"
        if chars & _RU_ONLY:
            return "ru"
        return "uz-Cyrl" if _looks_uzbek(transliterate(t)) else "ru"

    if lat_ratio >= 0.5:
        return "uz-Latn" if _looks_uzbek(t) else "en"

    return "unknown"


_UZ_STOPWORDS = {
    "va", "bilan", "uchun", "bu", "shu", "kerak", "yoq", "yo'q", "siz",
    "sizning", "men", "biz", "ham", "lekin", "agar", "hurmatli", "mijoz",
    "qiling", "yuboring", "kiriting", "tasdiqlang", "boladi", "bo'ladi",
    "bering", "oling", "keyin", "hozir", "bugun", "ertaga", "juda",
}

# Rus tiliga xos so'zlar (transliteratsiyadan keyingi ko'rinishda).
# "karta", "kod", "bank" kabi umumiy so'zlar ikkala tilda ham bor —
# ular til belgisi bo'la olmaydi va ro'yxatga kiritilmagan.
_RU_STOPWORDS = {
    "vash", "vasha", "vashe", "vashi", "eto", "etot", "dlya", "chto",
    "kotoriy", "bil", "bila", "budet", "esli", "ochen", "tolko", "uje",
    "pojaluysta", "uvajaemiy", "uvajaemaya", "klient", "danniye", "danni",
    "schet", "sluzhba", "bezopasnosti", "podtverdite", "zablokirovana",
    "zablokirovan", "operatsii", "perevod", "dengi", "nomer", "svoy",
    "nujno", "sroch no", "srochno", "nemedlenno", "ne", "vi", "mi",
}

# O'zbek tiliga xos qo'shimchalar — so'z oxiri bo'yicha
_UZ_SUFFIXES = ("ngiz", "ingiz", "lari", "ning", "dan", "ga", "da", "ni", "larda")


def _lang_scores(latin_text: str) -> tuple[int, int]:
    """(o'zbek balli, rus balli)"""
    words = re.findall(r"[a-z']+", latin_text.lower())
    uz = sum(1 for w in words if w in _UZ_STOPWORDS)
    ru = sum(1 for w in words if w in _RU_STOPWORDS)
    if any(m in latin_text for m in _UZ_LATIN_MARKERS):
        uz += 2
    uz += sum(1 for w in words if len(w) > 5 and w.endswith(_UZ_SUFFIXES))
    return uz, ru


def _looks_uzbek(latin_text: str) -> bool:
    uz, ru = _lang_scores(latin_text)
    return uz > ru


def normalize_text(text: str) -> tuple[str, str]:
    """(til, model uchun normallashtirilgan lotin matn) qaytaradi."""
    lang = detect_lang(text)
    t = normalize_apostrophes(text)
    if lang in ("uz-Cyrl", "ru", "mixed"):
        t = transliterate(t)
    return lang, re.sub(r"\s+", " ", t).strip()
