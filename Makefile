.PHONY: up down test lint db-reset train collect

up:        ## Tizimni ishga tushirish
	docker compose up -d --build

down:
	docker compose down

test:      ## Modul sinovlari + qamrov (NFT-11: >= 70%)
	python -m pytest tests/ -q --cov=app --cov-report=term-missing

lint:
	ruff check app ml tests

db-reset:  ## Sxemani qaytadan yaratish
	docker compose exec -T postgres psql -U ucw -d uzcyberwatch < db/001_schema.sql
	docker compose exec -T postgres psql -U ucw -d uzcyberwatch < db/002_seed.sql

train:     ## URL modelini o'qitish (TZ: QM-01..QM-05)
	python -m ml.train_url --data data/urls.csv --out ml/models/url_phish.joblib

collect:   ## CT log oqimini kuzatish (bazaga yozmasdan)
	python -m app.collectors.ct_log --dry-run
