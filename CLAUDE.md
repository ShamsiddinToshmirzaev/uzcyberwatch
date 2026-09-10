# UzCyberWatch — loyiha konteksti

Magistrlik dissertatsiyasining amaliy qismi: "O'zbekiston hududida sodir
bo'layotgan kiberjinoyatlarni avtomatik aniqlash va tahlil qilish tizimi".

Barcha talablar `docs/TZ.docx` da (GOST 34.602-89). Kodda talab kodlariga
havola qilinadi: **FT-xx** funksional, **NFT-xx** nofunksional, **HT-xx**
huquqiy-etik, **QM-xx** qabul mezoni.

## Tilga oid qoida

Kod izohlari, commit xabarlari va hujjatlar — **o'zbek tilida**.
O'zgaruvchi va funksiya nomlari — ingliz tilida (snake_case).

## Arxitektura

```
Collector → Normalizer → Enrichment → Detection Engine → Analytics/API
FT-01..09   FT-10..14    FT-15..20     FT-21..30          FT-31..48
```

Modullar joylashuvi:

| Yo'l | Vazifa |
|---|---|
| `app/collectors/` | Ma'lumot yig'ish (CT log, shikoyat, honeypot, TI feed) |
| `app/normalize/` | Til aniqlash, transliteratsiya, PII maskalash |
| `app/enrich/` | GeoIP, WHOIS, reputatsiya, skrinshot pHash |
| `app/detect/` | Gibrid aniqlash yadrosi |
| `ml/` | Model o'qitish skriptlari |
| `db/` | PostgreSQL sxemasi va seed |

## Buzilmasligi kerak bo'lgan qoidalar

1. **HT-03 — xom PII hech qachon bazaga yozilmaydi.** Telefon, karta,
   pasport, PINFL faqat `pii.pii_hash()` orqali HMAC-hesh va maskalangan
   hint ko'rinishida saqlanadi. Yangi maydon qo'shsangiz, avval
   `pii.redact()` dan o'tkazing.
2. **HT-05 — tizim huquqiy qaror qabul qilmaydi.** `legal_map.suggest()`
   natijasida `requires_review=True` doim saqlanadi.
3. **HT-07 — hujumkor funksiyalar taqiqlanadi.** Aktiv skanerlash,
   zaiflik ekspluatatsiyasi, parol tanlash, yopiq kanallarga kirish —
   loyiha doirasidan tashqarida. Faqat passiv, ochiq manba.
4. **FT-27 — har bir aniqlash sababi bo'lishi shart.** `Reason` obyektisiz
   ball berilmaydi; sababsiz ogohlantirish analitik uchun foydasiz.
5. **O'zbek tili agglyutinativ.** Regex naqshlarida so'z oxirida `\b`
   ishlatmang: "kod-ni", "karta-ngiz", "soat-da". Faqat boshida `\b`.
6. **Rasmiy domenlar hech qachon flag qilinmaydi.** `brands.OFFICIAL_DOMAINS`
   ga har qanday o'zgartirishdan keyin `test_official_domains_never_typosquat`
   o'tishi shart.

## Buyruqlar

```bash
make test      # pytest + qamrov (NFT-11: >= 70%)
make lint      # ruff
make up        # docker compose
make train     # URL modelini o'qitish
make collect   # CT log oqimi (dry-run)
```

## Hozirgi holat

Tayyor:
- `db/001_schema.sql` — to'liq sxema (12 jadval, append-only audit trigger)
- `app/detect/brands.py` — 30+ mahalliy brend, typosquat/homoglif/punycode
- `app/detect/text_rules.py` — 10 ta o'zbek/rus firibgarlik naqshi
- `app/detect/engine.py` — gibrid ballash + explainability
- `app/detect/legal_map.py` — JK moddalariga moslashtirish
- `app/normalize/lang.py`, `pii.py`
- `app/collectors/ct_log.py` — certstream
- `ml/train_url.py` — GBDT + baseline, QM tekshiruvi
- `tests/test_detect.py` — 31 test

Yozilmagan (keyingi sprintlar):
- `app/main.py` — FastAPI ilovasi (FT-46)
- `app/db.py`, `app/models.py` — SQLAlchemy qatlami
- `app/collectors/complaint_bot.py` — Telegram-bot (FT-04)
- `app/enrich/` — barcha modullar (FT-15..20)
- `app/detect/graph.py` — Neo4j/Louvain (FT-26)
- Frontend (FT-31..37)
- `data/urls.csv` — dataset yig'ilmagan (QM-18: >= 20 000)

## Ishlash uslubi

- Har bir yangi modul uchun avval test yozing, keyin implementatsiya.
- Har bir funksiya docstring'ida qaysi FT talabini bajarayotganini yozing.
- Tashqi API kalitlari `.env` da; kodda hech qachon hardcode qilinmaydi.
- Yangi dependency qo'shsangiz `requirements.txt` ga versiya bilan yozing.
