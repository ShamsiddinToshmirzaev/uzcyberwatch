# UzCyberWatch

O'zbekiston hududida sodir bo'layotgan kiberjinoyatlarni avtomatik aniqlash
va tahlil qilish tizimi. Magistrlik dissertatsiyasining amaliy qismi.

Talablar: `docs/TZ.docx` (GOST 34.602-89). Kodda FT-xx / NFT-xx / HT-xx / QM-xx
kodlari orqali havola qilinadi.

## Tez boshlash

```bash
git clone <repo> && cd uzcyberwatch
cp .env.example .env
# .env dagi UCW_PII_PEPPER ni ALBATTA o'zgartiring
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make test
```

Docker bilan (NFT-12: bir buyruqda ishga tushishi):

```bash
docker compose up -d --build
```

## Nima ishlaydi

Aniqlash yadrosi ML modelisiz ham to'liq ishlaydi — qoidaviy va evristik
qatlamlar mustaqil ball beradi:

```bash
python3 - <<'EOF'
from app.detect.engine import analyse
v = analyse(url="http://click-uz-tasdiqlash.xyz/login", domain_age_days=3)
print(v.risk_score, v.incident_type)
for r in v.reasons: print(f"  [{r.layer}] {r.code} +{r.weight} — {r.detail}")
EOF
```

CT log oqimini kuzatish (bazaga yozmasdan):

```bash
make collect
```

## Nima uchun mahalliy yechim kerak

Xalqaro fishing detektorlari `click.uz`, `payme.uz`, `humo.uz` kabi
brendlarni bilmaydi. `app/detect/brands.py` 30+ mahalliy brendni va
ularga taqlidning 4 xil turini aniqlaydi:

| Naqsh | Misol | Og'irlik |
|---|---|---|
| `subdomain_abuse` | `click.uz.tasdiqlash-hisob.com` | 45 |
| `homoglyph` | `сlick.uz` (kirill "с") | 40 |
| `typosquat` | `clik.uz`, `payme-kirish.net` | 35 |
| `keyword` | `bonus-pul.xyz` | 15 |

## Shaxsga doir ma'lumotlar

Xom PII bazaga yozilmaydi (HT-03). Telefon, karta, pasport va PINFL
kalitli HMAC-SHA256 hesh va maskalangan hint sifatida saqlanadi:

```
+998 90 123 45 67  ->  hint "+998 90 *** ** 67"  hash a6bc1fe929fdc9e5...
```

Karta raqami faqat Luhn tekshiruvidan o'tsa qayd etiladi — bu tasodifiy
16 xonali raqamlardan kelib chiqadigan noto'g'ri ijobiylarni yo'q qiladi.

## Cheklovlar

Bu **passiv, mudofaaviy** tizim. Aktiv skanerlash, zaiflik ekspluatatsiyasi,
yopiq kanallarga kirish yoki parol tanlash funksiyalari yo'q va qo'shilmaydi
(HT-07). Tizim huquqiy qaror qabul qilmaydi — JK moddasi bo'yicha tavsiya
beradi, yakuniy kvalifikatsiya vakolatli mutaxassisga tegishli (HT-05).

## Litsenziya

Akademik foydalanish uchun. Joriy etishdan oldin universitet etika
komissiyasi xulosasi talab qilinadi.
