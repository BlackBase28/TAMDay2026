CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Important',
    status TEXT NOT NULL DEFAULT 'Tracking',
    affected_versions TEXT NOT NULL,
    attack_vector TEXT NOT NULL,
    subsystem TEXT NOT NULL,
    summary TEXT NOT NULL,
    impact TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    reboot_required INTEGER NOT NULL DEFAULT 1,
    reference_url TEXT,
    published_date TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- Stored for quick review in the admin screen.  The JSONL file is the primary EDA-friendly log.
CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    event_outcome TEXT NOT NULL,
    failure_reason TEXT,
    username_attempted TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    http_path TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_cves_enabled ON cves(enabled);
CREATE INDEX IF NOT EXISTS idx_auth_events_time ON auth_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip ON auth_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_auth_events_user ON auth_events(username_attempted);
