ALTER TABLE nodes ADD COLUMN docker TEXT;

ALTER TABLE checks ADD COLUMN auto_restart INTEGER NOT NULL DEFAULT 0;

CREATE TABLE removed_stacks (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  project TEXT NOT NULL,
  directory TEXT NOT NULL,
  removed_at TEXT NOT NULL,
  PRIMARY KEY (node_id, project)
);

PRAGMA defer_foreign_keys = true;

CREATE TABLE actions_next (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('rolling', 'parallel')),
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN
    ('systemd', 'docker', 'compose', 'trust', 'host')),
  name TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN
    ('start', 'stop', 'restart', 'deploy', 'rollback', 'trust', 'reboot', 'logs',
     'remove', 'purge', 'restore', 'create', 'autorestart', 'manual', 'heal')),
  status TEXT NOT NULL CHECK (status IN
    ('queued', 'sent', 'done', 'failed', 'expired', 'cancelled', 'skipped')),
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  deliverable_at TEXT,
  sent_at TEXT,
  finished_at TEXT,
  exit_code INTEGER,
  output TEXT,
  signed TEXT,
  device_id TEXT
);

INSERT INTO actions_next (id, batch_id, position, mode, node_id, kind, name,
  action, status, requested_by, requested_at, deliverable_at, sent_at,
  finished_at, exit_code, output, signed, device_id)
SELECT id, batch_id, position, mode, node_id, kind, name, action, status,
  requested_by, requested_at, deliverable_at, sent_at, finished_at, exit_code,
  output, signed, device_id
FROM actions;

DROP TABLE actions;
ALTER TABLE actions_next RENAME TO actions;

CREATE INDEX idx_actions_status_node ON actions(status, node_id);
CREATE INDEX idx_actions_node_requested ON actions(node_id, requested_at);
CREATE INDEX idx_actions_batch ON actions(batch_id, position);
CREATE UNIQUE INDEX idx_actions_one_pending
  ON actions(node_id, kind, name)
  WHERE status IN ('queued', 'sent') AND action <> 'logs';
