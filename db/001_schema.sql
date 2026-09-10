-- UzCyberWatch — ma'lumotlar bazasi sxemasi
-- TZ: 4.3.2-band, 2-rasm (ER-diagramma)
-- PostgreSQL 15+ / TimescaleDB (ixtiyoriy)

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------- ENUM'lar
CREATE TYPE source_kind    AS ENUM ('ct_log','complaint','honeypot','ti_feed','manual');
CREATE TYPE event_type     AS ENUM ('url','domain','message','host_event','file');
CREATE TYPE detector_kind  AS ENUM ('rule','model','graph','heuristic');
CREATE TYPE case_status    AS ENUM ('new','triage','confirmed','false_positive','closed');
CREATE TYPE ioc_type       AS ENUM ('domain','url','ip','sha256','phone','card_bin','account','email');
CREATE TYPE user_role      AS ENUM ('analyst','investigator','admin','researcher','guest');

-- ---------------------------------------------------------------- FT-43,44: foydalanuvchilar
CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text        NOT NULL UNIQUE,
    password_hash text        NOT NULL,
    role          user_role   NOT NULL DEFAULT 'analyst',
    mfa_enabled   boolean     NOT NULL DEFAULT false,
    is_active     boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- FT-01..09: manbalar
CREATE TABLE sources (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind         source_kind NOT NULL,
    name         text        NOT NULL UNIQUE,
    config       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled      boolean     NOT NULL DEFAULT true,
    last_run_at  timestamptz,
    last_error   text,
    error_count  integer     NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------- FT-10..14: normallashtirilgan hodisalar
CREATE TABLE raw_events (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id    uuid        NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
    event_type   event_type  NOT NULL,
    -- FT-13: PII maskalangan holda saqlanadi
    content      text        NOT NULL,
    url          text,
    domain       text,
    lang         text,                       -- uz-Latn | uz-Cyrl | ru | en | mixed
    dedup_hash   text        NOT NULL,
    ecs          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    observed_at  timestamptz NOT NULL DEFAULT now(),
    ingested_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_raw_events_dedup UNIQUE (dedup_hash)
);
CREATE INDEX idx_raw_events_observed  ON raw_events (observed_at DESC);
CREATE INDEX idx_raw_events_domain    ON raw_events (domain) WHERE domain IS NOT NULL;
CREATE INDEX idx_raw_events_type_time ON raw_events (event_type, observed_at DESC);
CREATE INDEX idx_raw_events_ecs       ON raw_events USING gin (ecs);

-- ---------------------------------------------------------------- FT-15..20: boyitish
CREATE TABLE enrichments (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id         uuid        NOT NULL UNIQUE REFERENCES raw_events(id) ON DELETE CASCADE,
    ip               inet,
    asn              text,
    asn_org          text,
    geo_country      text,
    geo_region       text,                   -- O'zbekiston viloyatlari
    domain_age_days  integer,
    registrar        text,
    cert_issuer      text,
    screenshot_phash text,
    reputation       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enriched_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_enrichments_region ON enrichments (geo_region);
CREATE INDEX idx_enrichments_phash  ON enrichments (screenshot_phash) WHERE screenshot_phash IS NOT NULL;

-- ---------------------------------------------------------------- FT-22,26: IoC va graf
-- HT-03: qiymat xom holda emas, HMAC-hesh sifatida saqlanadi
CREATE TABLE indicators (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type    ioc_type    NOT NULL,
    value_hash  text        NOT NULL,
    value_hint  text,                        -- maskalangan ko'rinish: +998 90 *** ** 12
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    hit_count   integer     NOT NULL DEFAULT 1,
    CONSTRAINT uq_indicator UNIQUE (ioc_type, value_hash)
);
CREATE INDEX idx_indicators_last_seen ON indicators (last_seen DESC);

CREATE TABLE event_indicators (
    event_id     uuid NOT NULL REFERENCES raw_events(id) ON DELETE CASCADE,
    indicator_id uuid NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    PRIMARY KEY (event_id, indicator_id)
);

-- graf qirralari: firibgar guruhlarni aniqlash uchun (FT-26)
CREATE TABLE indicator_edges (
    src_id     uuid    NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    dst_id     uuid    NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    weight     integer NOT NULL DEFAULT 1,
    community  integer,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (src_id, dst_id),
    CONSTRAINT chk_no_self_loop CHECK (src_id <> dst_id)
);
CREATE INDEX idx_edges_community ON indicator_edges (community) WHERE community IS NOT NULL;

-- ---------------------------------------------------------------- FT-21..30: detektorlar
CREATE TABLE detectors (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       detector_kind NOT NULL,
    name       text          NOT NULL,
    version    text          NOT NULL DEFAULT '1.0',
    enabled    boolean       NOT NULL DEFAULT true,
    params     jsonb         NOT NULL DEFAULT '{}'::jsonb,
    f1_score   real,
    precision  real,
    recall     real,
    trained_at timestamptz,
    CONSTRAINT uq_detector UNIQUE (name, version)
);

-- ---------------------------------------------------------------- FT-28: JK moddalari ma'lumotnomasi
CREATE TABLE legal_articles (
    code       text PRIMARY KEY,             -- '278-1', '168-4' ...
    chapter    text NOT NULL,
    title_uz   text NOT NULL,
    severity   text NOT NULL,
    notes      text
);

-- ---------------------------------------------------------------- ish yuritish
CREATE TABLE cases (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    assignee_id  uuid REFERENCES users(id) ON DELETE SET NULL,
    article_code text REFERENCES legal_articles(code) ON DELETE SET NULL,
    article_conf real,                        -- moslashtirish ishonchliligi
    status       case_status NOT NULL DEFAULT 'new',
    title        text        NOT NULL,
    region       text,
    total_risk   integer     NOT NULL DEFAULT 0,
    opened_at    timestamptz NOT NULL DEFAULT now(),
    closed_at    timestamptz,
    CONSTRAINT chk_total_risk CHECK (total_risk BETWEEN 0 AND 100)
);
CREATE INDEX idx_cases_status ON cases (status, opened_at DESC);
CREATE INDEX idx_cases_region ON cases (region);

CREATE TABLE detections (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id    uuid NOT NULL REFERENCES raw_events(id) ON DELETE CASCADE,
    detector_id uuid NOT NULL REFERENCES detectors(id) ON DELETE RESTRICT,
    case_id     uuid REFERENCES cases(id) ON DELETE SET NULL,
    confidence  real    NOT NULL,
    risk_score  integer NOT NULL,
    explanation jsonb   NOT NULL DEFAULT '[]'::jsonb,   -- FT-27: sabablar ro'yxati
    detected_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_conf CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT chk_risk CHECK (risk_score BETWEEN 0 AND 100),
    CONSTRAINT uq_detection UNIQUE (event_id, detector_id)
);
CREATE INDEX idx_detections_time ON detections (detected_at DESC);
CREATE INDEX idx_detections_risk ON detections (risk_score DESC);
CREATE INDEX idx_detections_case ON detections (case_id) WHERE case_id IS NOT NULL;

-- ---------------------------------------------------------------- FT-40,41: dalil zanjiri
CREATE TABLE evidence (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       uuid NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    artifact_type text NOT NULL,             -- screenshot | har | pcap | export | source_html
    sha256        text NOT NULL,
    storage_path  text NOT NULL,
    collected_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    collected_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_evidence_hash UNIQUE (case_id, sha256)
);

-- ---------------------------------------------------------------- dataset belgilash (QM-18, QM-19)
CREATE TABLE labels (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id       uuid NOT NULL REFERENCES raw_events(id) ON DELETE CASCADE,
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    class_label    text NOT NULL,            -- phishing | fraud_text | benign | spam | unknown
    annotator_conf real NOT NULL DEFAULT 1.0,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_label_per_user UNIQUE (event_id, user_id)
);
CREATE INDEX idx_labels_class ON labels (class_label);

-- ---------------------------------------------------------------- FT-45: o'zgartirilmas audit
CREATE TABLE audit_log (
    id         bigserial PRIMARY KEY,
    user_id    uuid REFERENCES users(id) ON DELETE SET NULL,
    action     text NOT NULL,
    object_ref text,
    ip         inet,
    details    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_time ON audit_log (created_at DESC);

REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;

CREATE OR REPLACE FUNCTION audit_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log append-only: UPDATE/DELETE taqiqlangan';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_immutable();

-- ---------------------------------------------------------------- tahlil uchun ko'rinish
CREATE VIEW v_region_daily AS
SELECT date_trunc('day', d.detected_at) AS day,
       COALESCE(e.geo_region, 'unknown') AS region,
       count(*)                          AS detections,
       avg(d.risk_score)::numeric(5,2)   AS avg_risk
FROM detections d
JOIN raw_events  r ON r.id = d.event_id
LEFT JOIN enrichments e ON e.event_id = r.id
GROUP BY 1, 2;
