-- Recon Automation Database Schema
-- Idempotent: safe to run on every startup

CREATE TABLE IF NOT EXISTS runs (
    id              BIGSERIAL PRIMARY KEY,
    run_uuid        UUID NOT NULL DEFAULT gen_random_uuid(),
    target_domain   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running','completed','failed','partial')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    tool_versions   JSONB,
    error_message   TEXT,
    total_subdomains INTEGER,
    total_ips        INTEGER,
    total_ports      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_runs_domain_started ON runs (target_domain, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs (status);

CREATE TABLE IF NOT EXISTS subdomains (
    id              BIGSERIAL PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    input_domain    TEXT NOT NULL,
    sources         TEXT[],
    first_seen_run  BIGINT REFERENCES runs(id),
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_subdomains_run_host ON subdomains (run_id, host);
CREATE INDEX IF NOT EXISTS idx_subdomains_host ON subdomains (host);
CREATE INDEX IF NOT EXISTS idx_subdomains_run_id ON subdomains (run_id);

CREATE TABLE IF NOT EXISTS dns_records (
    id              BIGSERIAL PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    record_type     TEXT NOT NULL,
    value           TEXT NOT NULL,
    status_code     TEXT,
    resolver        TEXT,
    timestamp       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_dns_run_host ON dns_records (run_id, host);
CREATE INDEX IF NOT EXISTS idx_dns_host_type ON dns_records (host, record_type);

CREATE TABLE IF NOT EXISTS ports (
    id              BIGSERIAL PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ip              TEXT NOT NULL,
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol        TEXT NOT NULL DEFAULT 'tcp',
    host            TEXT,
    service         TEXT,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_run_ip_port ON ports (run_id, ip, port, protocol);
CREATE INDEX IF NOT EXISTS idx_ports_run_id ON ports (run_id);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports (port);

CREATE TABLE IF NOT EXISTS asn_records (
    id              BIGSERIAL PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    input           TEXT NOT NULL,
    as_number       INTEGER,
    as_name         TEXT,
    as_country      TEXT,
    as_ranges       TEXT[],
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asn_run_id ON asn_records (run_id);

CREATE TABLE IF NOT EXISTS cert_transparency (
    id              BIGSERIAL PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    domain          TEXT NOT NULL,
    san_domains     TEXT[],
    issuer          TEXT,
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    serial_number   TEXT,
    fingerprint     TEXT,
    log_source      TEXT,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ct_domain ON cert_transparency (domain);

CREATE TABLE IF NOT EXISTS run_diffs (
    id              BIGSERIAL PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    prev_run_id     BIGINT REFERENCES runs(id) ON DELETE SET NULL,
    diff_type       TEXT NOT NULL CHECK (diff_type IN ('subdomain','port','dns','asn')),
    change_type     TEXT NOT NULL CHECK (change_type IN ('added','removed')),
    target_domain   TEXT NOT NULL,
    value           TEXT NOT NULL,
    metadata        JSONB,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_diffs_run_id ON run_diffs (run_id);
CREATE INDEX IF NOT EXISTS idx_diffs_type_change ON run_diffs (diff_type, change_type);
CREATE INDEX IF NOT EXISTS idx_diffs_detected_at ON run_diffs (detected_at DESC);

-- Views for Grafana

CREATE OR REPLACE VIEW v_subdomain_counts AS
SELECT
    r.id            AS run_id,
    r.target_domain,
    r.started_at,
    r.finished_at,
    r.status,
    COUNT(s.id)     AS subdomain_count
FROM runs r
LEFT JOIN subdomains s ON s.run_id = r.id
WHERE r.status IN ('completed','partial')
GROUP BY r.id, r.target_domain, r.started_at, r.finished_at, r.status;

CREATE OR REPLACE VIEW v_diff_summary AS
SELECT
    rd.run_id,
    r.target_domain,
    r.started_at,
    rd.diff_type,
    rd.change_type,
    COUNT(*) AS change_count
FROM run_diffs rd
JOIN runs r ON r.id = rd.run_id
GROUP BY rd.run_id, r.target_domain, r.started_at, rd.diff_type, rd.change_type;

CREATE OR REPLACE VIEW v_port_distribution AS
SELECT
    p.port,
    p.protocol,
    CASE
        WHEN p.port = 21   THEN 'ftp'
        WHEN p.port = 22   THEN 'ssh'
        WHEN p.port = 25   THEN 'smtp'
        WHEN p.port = 53   THEN 'dns'
        WHEN p.port = 80   THEN 'http'
        WHEN p.port = 110  THEN 'pop3'
        WHEN p.port = 143  THEN 'imap'
        WHEN p.port = 443  THEN 'https'
        WHEN p.port = 3306 THEN 'mysql'
        WHEN p.port = 5432 THEN 'postgres'
        WHEN p.port = 6379 THEN 'redis'
        WHEN p.port = 8080 THEN 'http-alt'
        WHEN p.port = 8443 THEN 'https-alt'
        WHEN p.port = 27017 THEN 'mongodb'
        ELSE 'other'
    END AS service_label,
    COUNT(DISTINCT p.ip) AS unique_ips,
    COUNT(DISTINCT p.run_id) AS seen_in_runs,
    MAX(r.started_at) AS last_seen
FROM ports p
JOIN runs r ON r.id = p.run_id
GROUP BY p.port, p.protocol, service_label
ORDER BY unique_ips DESC;
