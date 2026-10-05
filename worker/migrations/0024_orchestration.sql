ALTER TABLE nodes ADD COLUMN seal_key TEXT;

ALTER TABLE nodes ADD COLUMN security TEXT;

ALTER TABLE nodes ADD COLUMN vault TEXT;

ALTER TABLE stacks ADD COLUMN access TEXT;

ALTER TABLE stacks ADD COLUMN public TEXT;

CREATE TABLE web_addresses (
  hostname TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  project TEXT NOT NULL,
  service TEXT NOT NULL,
  port INTEGER NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('allow', 'path', 'everyone')),
  path TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT
);

CREATE INDEX idx_web_addresses_node ON web_addresses(node_id, project);

CREATE TABLE cloudflare (
  owner_user_id TEXT PRIMARY KEY,
  zone TEXT NOT NULL,
  set_id TEXT,
  updated_at TEXT NOT NULL,
  reminded_at TEXT
);

PRAGMA defer_foreign_keys = true;

CREATE TABLE actions_next (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('rolling', 'parallel')),
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN
    ('systemd', 'docker', 'compose', 'trust', 'host', 'vault')),
  name TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN
    ('start', 'stop', 'restart', 'deploy', 'rollback', 'trust', 'reboot', 'logs',
     'remove', 'purge', 'restore', 'create', 'autorestart', 'manual', 'heal',
     'edit', 'read', 'export', 'expose', 'unexpose', 'adopt',
     'apply', 'undo', 'lockdown', 'unlock', 'scan',
     'store', 'release', 'reshare', 'forget')),
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
  device_id TEXT,
  attachment TEXT,
  attach_from INTEGER,
  attach_key TEXT
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
  WHERE status IN ('queued', 'sent')
    AND action NOT IN ('logs', 'read', 'export', 'expose', 'unexpose', 'scan',
      'store', 'release', 'reshare', 'forget');
