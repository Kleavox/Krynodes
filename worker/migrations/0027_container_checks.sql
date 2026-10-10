PRAGMA defer_foreign_keys = true;

CREATE TABLE incidents_keep AS SELECT * FROM incidents;

CREATE TABLE checks_next (
  id TEXT PRIMARY KEY,
  node_id TEXT REFERENCES nodes(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('HTTP', 'TCP', 'SERVICE', 'CONTAINER')),
  target TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'UNKNOWN'
    CHECK (status IN ('UNKNOWN', 'UP', 'DOWN')),
  timeout_seconds INTEGER NOT NULL DEFAULT 10,
  latency_ms INTEGER,
  last_checked_at TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_message TEXT,
  public INTEGER NOT NULL DEFAULT 0,
  public_note TEXT,
  auto_restart INTEGER NOT NULL DEFAULT 0
);

INSERT INTO checks_next (id, node_id, name, kind, target, enabled, created_at,
  updated_at, status, timeout_seconds, latency_ms, last_checked_at,
  consecutive_failures, last_message, public, public_note, auto_restart)
SELECT id, node_id, name, kind, target, enabled, created_at, updated_at, status,
  timeout_seconds, latency_ms, last_checked_at, consecutive_failures,
  last_message, public, public_note, auto_restart
FROM checks;

DROP TABLE checks;

ALTER TABLE checks_next RENAME TO checks;

CREATE INDEX idx_checks_node_id ON checks(node_id);

CREATE INDEX idx_checks_public_updated ON checks(public, updated_at);

INSERT INTO incidents (id, check_id, status, started_at, resolved_at, summary)
SELECT id, check_id, status, started_at, resolved_at, summary FROM incidents_keep
WHERE id NOT IN (SELECT id FROM incidents);

DROP TABLE incidents_keep;
