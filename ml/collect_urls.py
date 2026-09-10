"""URL dataset yig'uvchi va generatsiya qiluvchi skript.

TZ: QM-18 — kamida 20 000 namuna (url,label).
label: 1 = phishing, 0 = yaxshi (benign).

Yondashuv: Deterministik sintetik dataset (random.seed=42).
  Phishing (label=1) — 10 xil naqsh: typosquat, IP, xavfli TLD,
    subdomen suiiste'moli, vasvasali so'zlar, @ trick, g'ayrioddiy port.
  Yaxshi  (label=0) — rasmiy bank/hukumat/ta'lim/xalqaro domenlar.

Foydalanish:
    python -m ml.collect_urls --out data/urls.csv
"""
from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

# ============================================================== Konstantalar

_BRAND_TLD: dict[str, str] = {
    "click":        "uz",
    "payme":        "uz",
    "paynet":       "uz",
    "uzum":         "uz",
    "apelsin":      "uz",
    "oson":         "uz",
    "uzcard":       "uz",
    "humo":         "uz",
    "nbu":          "uz",
    "sqb":          "uz",
    "asakabank":    "uz",
    "agrobank":     "uz",
    "xalqbank":     "uz",
    "kapitalbank":  "uz",
    "ipotekabank":  "uz",
    "infinbank":    "uz",
    "anorbank":     "uz",
    "tbcbank":      "uz",
    "hamkorbank":   "uz",
    "ipakyulibank": "uz",
    "trastbank":    "uz",
    "texagrobank":  "uz",
    "aloqabank":    "uz",
    "pochtabank":   "uz",
    "uzpost":       "uz",
}

_RISKY_TLDS = (
    "tk", "ml", "ga", "cf", "gq", "xyz", "top",
    "buzz", "site", "online", "click", "rest", "info",
)

_LURE_WORDS = (
    "login", "kirish", "secure", "xavfsiz", "verify", "tasdiqlash",
    "confirm", "account", "hisob", "pay", "payment", "banking",
    "cards", "activate", "transfer", "tolov", "bank",
)

_PREFIXES = ("my-", "secure-", "login-", "verify-", "online-",
             "new-", "official-", "real-", "best-", "uz-")

_SUFFIXES = ("-online", "-secure", "-login", "-uz", "-pay",
             "-bank", "-card", "-2024", "-net", "-service")

_WRONG_TLDS = ("com", "ru", "net", "org", "kz", "io", "co")

_PATHS_PHISH = (
    "/login", "/kirish", "/verify", "/confirm", "/auth",
    "/account/verify", "/secure/login", "/payment/confirm",
    "/banking/login", "/cards/activate", "/transfer",
    "/p?redirect=true", "/login?next=%2Faccount",
    "/hisob", "/tolov", "/karta/faollashtirish",
)

_PATHS_BENIGN = (
    "/", "/about", "/about-us", "/contact", "/services",
    "/products", "/blog", "/news", "/ru", "/uz", "/en",
    "/support", "/faq", "/help", "/sitemap.xml",
    "/login", "/register", "/privacy", "/terms",
    "/search", "/category/news", "/category/services",
    "/2024/", "/download", "/user/profile", "/settings",
    "/dashboard", "/analytics", "/report", "/home",
    "/docs", "/wiki", "/api/v1/health", "/robots.txt",
    "/main", "/index.html", "/products/list", "/offers",
    "/ru/about", "/uz/hizmatlar", "/en/services",
    "/mobile", "/app", "/banking", "/cards",
    "/transfer", "/payments", "/history", "/profile",
    "/notifications", "/messages", "/security", "/logout",
    "/api", "/media", "/uploads", "/static/css/main.css",
)

_BENIGN_SEEDS = (
    # O'zbek banklari va to'lov tizimlari (rasmiy)
    "click.uz", "payme.uz", "paynet.uz", "uzum.uz", "apelsin.uz",
    "oson.uz", "uzcard.uz", "humo.uz", "nbu.uz", "sqb.uz",
    "asakabank.uz", "agrobank.uz", "xalqbank.uz", "xb.uz",
    "kapitalbank.uz", "ipotekabank.uz", "infinbank.uz",
    "anorbank.uz", "tbcbank.uz", "hamkorbank.uz",
    "ipakyulibank.uz", "trastbank.uz", "aloqabank.uz",
    "pochtabank.uz", "texagrobank.uz",
    # Hukumat
    "gov.uz", "mf.uz", "customs.uz", "stat.uz", "parlament.uz",
    "president.uz", "court.uz", "prokuratura.uz", "soliq.uz",
    "ijro.uz", "yoshlar.uz", "mehnat.uz", "sog-liqni-saqlash.uz",
    # Ta'lim
    "edu.uz", "tuit.uz", "nuu.uz", "tma.uz", "mdis.uz",
    "samdu.uz", "tdiu.uz", "pharmi.uz", "tsue.uz", "bibim.uz",
    # Yangiliklar va media
    "kun.uz", "gazeta.uz", "uza.uz", "xs.uz", "daryo.uz",
    "qalampir.uz", "dunyo.uz", "podrobno.uz", "zamin.uz",
    "sputniknews.uz", "interfax.uz", "spot.uz", "kommersant.uz",
    # Xizmatlar
    "uzb.uz", "humans.uz", "mytaxi.uz", "yandex.uz",
    "e-gov.uz", "my.gov.uz", "license.uz", "epay.uz",
    "ems.uz", "pochta.uz", "uzinfocom.uz", "uznet.uz",
    # Xalqaro — katta saytlar
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "linkedin.com", "wikipedia.org", "amazon.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "cloudflare.com", "netflix.com", "reddit.com", "gmail.com",
    "yahoo.com", "bing.com", "outlook.com", "office.com",
    "adobe.com", "dropbox.com", "zoom.us", "slack.com",
    "wordpress.com", "wix.com", "shopify.com", "ebay.com",
    "paypal.com", "visa.com", "mastercard.com", "stripe.com",
    # Yangiliklar xalqaro
    "bbc.com", "cnn.com", "reuters.com", "nytimes.com",
    "theguardian.com", "forbes.com", "bloomberg.com", "wsj.com",
    "ft.com", "economist.com", "nature.com", "science.org",
    # Texnologiya
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
    "developer.mozilla.org", "docs.python.org", "pypi.org",
    "npmjs.com", "hub.docker.com", "kubernetes.io",
)

# ============================================================== Generator funksiyalar

def _typosquat(brand: str) -> list[str]:
    """Brend nomiga o'xshash, ammo noto'g'ri domenlar (typosquat).

    TZ: FT-21 — brendlarga taqlid qiluvchi domenlarni aniqlash uchun
    sintetik misollar.
    """
    variants: set[str] = set()
    n = len(brand)

    # 1. Belgi olib tashlash (missing character)
    for i in range(n):
        v = brand[:i] + brand[i + 1:]
        if len(v) >= 3:
            variants.add(v)

    # 2. Qo'shni belgilarni almashtirish (transposition)
    for i in range(n - 1):
        b = list(brand)
        b[i], b[i + 1] = b[i + 1], b[i]
        v = "".join(b)
        if v != brand:
            variants.add(v)

    # 3. Defis qo'shish (hyphen insertion)
    for i in range(1, n):
        variants.add(f"{brand[:i]}-{brand[i:]}")

    # 4. Prefix va suffix (social engineering)
    for pre in _PREFIXES:
        variants.add(f"{pre}{brand}")
    for suf in _SUFFIXES:
        variants.add(f"{brand}{suf}")

    # 5. Raqam almashtirish (leetspeak)
    leet = str.maketrans("aeiols", "431015")
    leet_v = brand.translate(leet)
    if leet_v != brand:
        variants.add(leet_v)

    # 6. Ikkilantirish — oxirgi harf
    variants.add(brand + brand[-1])

    # TLD bilan to'ldirish
    result: list[str] = []
    for v in variants:
        if not v or v == brand:
            continue
        # Brend bilan bir xil TLD (.uz) va boshqa TLDlar
        result.append(f"{v}.uz")
        for tld in _WRONG_TLDS:
            result.append(f"{v}.{tld}")
    return result


def _free_tld(brand: str) -> list[str]:
    """Xavfli/bepul TLDlarda brend domenlari."""
    return [f"{brand}.{tld}" for tld in _RISKY_TLDS]


def _subdomain_abuse(brand: str, tld: str) -> list[str]:
    """Rasmiy domen subdomen sifatida ishlatilgan domenlar.

    Masalan: kapitalbank.uz.phishing-site.com
    """
    official = f"{brand}.{tld}"
    return [
        f"{official}.login-secure.com",
        f"{official}.account-verify.net",
        f"{official}.payment-confirm.ru",
        f"secure-{official}.phish.xyz",
        f"verify.{brand}-{tld}.com",
        f"{brand}-{tld}.verify-account.net",
        f"login.{official}.malicious.top",
    ]


def _lure_combo(brand: str) -> list[str]:
    """Vasvasali so'zlar bilan domen kombinatsiyalari."""
    result = []
    for lure in _LURE_WORDS[:10]:
        result.append(f"{brand}-{lure}.com")
        result.append(f"{lure}-{brand}.uz")
        result.append(f"{brand}{lure}.com")
    return result


# ============================================================== Asosiy generatorlar

def generate_phishing(seed: int = 42) -> list[str]:
    """Phishing URLlar ro'yxatini generatsiya qilish (label=1).

    10 xil naqsh: typosquat, IP, xavfli TLD, subdomen suiiste'moli,
    vasvasali so'zlar, @ trick, g'ayrioddiy port, chuqur subdomen.
    """
    rng = random.Random(seed)
    urls: set[str] = set()

    for brand, tld in _BRAND_TLD.items():
        # 1. Typosquat domenlar
        for dom in _typosquat(brand):
            for path in rng.sample(_PATHS_PHISH, k=min(6, len(_PATHS_PHISH))):
                urls.add(f"http://{dom}{path}")

        # 2. Xavfli TLD
        for dom in _free_tld(brand):
            for path in rng.sample(_PATHS_PHISH, k=4):
                urls.add(f"http://{dom}{path}")

        # 3. Subdomen suiiste'moli
        for dom in _subdomain_abuse(brand, tld):
            for path in rng.sample(_PATHS_PHISH, k=3):
                urls.add(f"http://{dom}{path}")

        # 4. Vasvasali so'z kombinatsiyalari
        for dom in _lure_combo(brand):
            for path in rng.sample(_PATHS_PHISH, k=3):
                urls.add(f"http://{dom}{path}")

        # 5. @ trick (haqiqiy host yashirish)
        attackers = [f"malicious{i:03d}.com" for i in range(15)]
        for att in attackers:
            urls.add(f"https://{brand}.{tld}@{att}/login")
            urls.add(f"http://{brand}.{tld}@{att}/kirish")

        # 6. G'ayrioddiy portlar — faqat typosquat domenlar bilan
        #    (rasmiy domenlar, masalan kapitalbank.uz:8080, phishing emas)
        for typo in _typosquat(brand)[:6]:
            for port in (8080, 8443, 9090, 3000):
                urls.add(f"http://{typo}:{port}/login")

        # 7. Chuqur subdomenlar (deep subdomain)
        for i in range(5):
            deep = f"login.secure.account{i}.{brand}.{tld}.phish.com"
            urls.add(f"http://{deep}/auth")

    # 8. IP asosidagi URLlar (2 500 ta)
    for _ in range(2500):
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        brand = rng.choice(list(_BRAND_TLD))
        path  = rng.choice(_PATHS_PHISH)
        urls.add(f"http://{ip}/{brand}{path}")
        urls.add(f"http://{ip}:8080/{brand}{path}")

    # 9. Yuqori entropiyali tasodifiy domenlar
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(1000):
        length = rng.randint(10, 22)
        dom = "".join(rng.choices(chars, k=length))
        tld = rng.choice(_RISKY_TLDS)
        path = rng.choice(_PATHS_PHISH)
        urls.add(f"http://{dom}.{tld}{path}")

    # 10. HTTP (TLS yo'q) versiyalari — rasmiy domenlar emas
    for brand, tld in list(_BRAND_TLD.items())[:15]:
        for typo in _typosquat(brand)[:10]:
            urls.add(f"http://{typo}/")

    return list(urls)


def generate_benign(seed: int = 42) -> list[str]:
    """Yaxshi URLlar ro'yxatini generatsiya qilish (label=0).

    Rasmiy bank, hukumat, ta'lim, yangiliklar va xalqaro domenlar
    turli yo'llar bilan kengaytiriladi.
    """
    rng = random.Random(seed)
    urls: set[str] = set()

    for domain in _BENIGN_SEEDS:
        for path in rng.sample(_PATHS_BENIGN, k=min(55, len(_PATHS_BENIGN))):
            scheme = "https"
            urls.add(f"{scheme}://{domain}{path}")
        # www. versiyasi
        if not domain.startswith("www."):
            for path in rng.sample(_PATHS_BENIGN, k=20):
                urls.add(f"https://www.{domain}{path}")

    return list(urls)


# ============================================================== Dataset qurish

_MAX_PER_CLASS = 15_000  # Sinf nomutanosibligini oldini olish uchun

def build_dataset(seed: int = 42) -> list[tuple[str, int]]:
    """Phishing va yaxshi URLlarni birlashtirgan balanced dataset.

    QM-18: Jami ≥ 20 000 namuna. Har bir sinf maksimal
    _MAX_PER_CLASS bilan cheklanadi — nomutanosiblikni kamaytiradi.

    Returns:
        [(url, label), ...] — label 0 yoki 1, takroriy URLsiz.
    """
    rng = random.Random(seed)

    phishing_urls = list(dict.fromkeys(generate_phishing(seed=seed)))
    benign_urls   = list(dict.fromkeys(generate_benign(seed=seed)))

    # Har bir sinfni _MAX_PER_CLASS bilan cheklash
    if len(phishing_urls) > _MAX_PER_CLASS:
        phishing_urls = rng.sample(phishing_urls, _MAX_PER_CLASS)
    if len(benign_urls) > _MAX_PER_CLASS:
        benign_urls = rng.sample(benign_urls, _MAX_PER_CLASS)

    rows: list[tuple[str, int]] = (
        [(u, 1) for u in phishing_urls] +
        [(u, 0) for u in benign_urls]
    )
    rng.shuffle(rows)
    return rows


# ============================================================== CSV saqlash

def save_dataset(path: Path | str, rows: list[tuple[str, int]]) -> int:
    """Dataset ni CSV formatda saqlash.

    Returns:
        Saqlangan satr soni.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    return len(rows)


# ============================================================== CLI

def main() -> int:
    ap = argparse.ArgumentParser(
        description="UzCyberWatch URL dataset generatsiya qiluvchi (QM-18)"
    )
    ap.add_argument("--out",  type=Path, default=Path("data/urls.csv"))
    ap.add_argument("--seed", type=int,  default=42)
    args = ap.parse_args()

    print("Dataset generatsiya qilinmoqda…")
    rows = build_dataset(seed=args.seed)

    phishing = sum(1 for _, l in rows if l == 1)
    benign   = sum(1 for _, l in rows if l == 0)
    print(f"  Jami:     {len(rows):>7,}")
    print(f"  Phishing: {phishing:>7,} ({phishing/len(rows):.1%})")
    print(f"  Yaxshi:   {benign:>7,} ({benign/len(rows):.1%})")

    n = save_dataset(args.out, rows)
    print(f"Saqlandi: {args.out}  ({n:,} satr)")

    if n < 20_000:
        print(f"OGOHLANTIRISH: QM-18 bajarilmadi ({n} < 20 000)")
        return 1
    print("QM-18: ✓ talab bajarildi")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
