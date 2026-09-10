FROM python:3.12-slim

WORKDIR /srv
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/srv

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# NFT: konteyner root sifatida ishlamaydi
RUN useradd -m ucw && chown -R ucw /srv
USER ucw

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
