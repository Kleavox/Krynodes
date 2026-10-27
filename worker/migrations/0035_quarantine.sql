CREATE TABLE network_documents (
  owner_user_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  document TEXT NOT NULL,
  PRIMARY KEY (owner_user_id, version)
);

INSERT INTO network_documents (owner_user_id, version, document)
  SELECT owner_user_id, version, document FROM network;

PRAGMA defer_foreign_keys = true;

CREATE TABLE actions_next (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('rolling', 'parallel')),
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN
    ('systemd', 'docker', 'compose', 'trust', 'host', 'vault', 'apt', 'network')),
  name TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN
    ('start', 'stop', 'restart', 'deploy', 'rollback', 'trust', 'reboot', 'logs',
     'remove', 'purge', 'restore', 'create', 'autorestart', 'manual', 'heal',
     'edit', 'read', 'export', 'expose', 'unexpose', 'adopt', 'reach',
     'apply', 'undo', 'lockdown', 'unlock', 'scan',
     'store', 'release', 'reshare', 'forget', 'install', 'uninstall',
     'signin', 'refresh', 'find', 'preview', 'upgrade', 'hold', 'unhold',
     'addrepo', 'droprepo',
     'inspect', 'probe', 'test', 'prepare', 'unprepare', 'rekey',
     'accept', 'block', 'unblock', 'drop', 'tighten')),
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
  attach_key TEXT,
  hidden_at TEXT,
  hidden_by TEXT,
  progress TEXT
);

INSERT INTO actions_next (id, batch_id, position, mode, node_id, kind, name,
  action, status, requested_by, requested_at, deliverable_at, sent_at,
  finished_at, exit_code, output, signed, device_id, attachment, attach_from,
  attach_key, hidden_at, hidden_by, progress)
SELECT id, batch_id, position, mode, node_id, kind, name, action, status,
  requested_by, requested_at, deliverable_at, sent_at, finished_at, exit_code,
  output, signed, device_id, attachment, attach_from, attach_key, hidden_at,
  hidden_by, progress
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
      'store', 'release', 'reshare', 'forget', 'refresh', 'find', 'preview',
      'inspect', 'probe', 'test',
      'lockdown', 'accept', 'block', 'unblock', 'drop', 'tighten');

ALTER TABLE nodes ADD COLUMN boot TEXT;
ALTER TABLE nodes ADD COLUMN reports INTEGER;
ALTER TABLE nodes ADD COLUMN release TEXT;

CREATE TABLE quarantine_settings (
  owner_user_id TEXT PRIMARY KEY,
  cutoff INTEGER,
  scan INTEGER NOT NULL,
  agree INTEGER NOT NULL,
  stop INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE warnings (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  id TEXT NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL,
  at TEXT NOT NULL,
  cut_at TEXT,
  answer TEXT,
  answered_at TEXT,
  answered_by TEXT,
  PRIMARY KEY (node_id, id)
);

CREATE TABLE knocks (
  suspect TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  reporter TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  at TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (suspect, reporter)
);

CREATE TABLE quarantines (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  why TEXT NOT NULL,
  at TEXT NOT NULL,
  timeline TEXT NOT NULL,
  released_at TEXT,
  released_by TEXT
);

CREATE UNIQUE INDEX idx_quarantines_open ON quarantines(node_id)
  WHERE released_at IS NULL;

CREATE TABLE stopped_stacks (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  project TEXT NOT NULL,
  at TEXT NOT NULL,
  tried TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, project)
);
