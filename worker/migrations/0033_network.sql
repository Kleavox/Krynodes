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
     'edit', 'read', 'export', 'expose', 'unexpose', 'adopt',
     'apply', 'undo', 'lockdown', 'unlock', 'scan',
     'store', 'release', 'reshare', 'forget', 'install', 'uninstall',
     'signin', 'refresh', 'find', 'preview', 'upgrade', 'hold', 'unhold',
     'addrepo', 'droprepo',
     'inspect', 'probe', 'test', 'prepare', 'unprepare', 'rekey')),
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
      'inspect', 'probe', 'test');

CREATE TABLE network (
  owner_user_id TEXT PRIMARY KEY,
  cidr TEXT NOT NULL,
  port INTEGER NOT NULL,
  mtu INTEGER NOT NULL,
  version INTEGER NOT NULL,
  document TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  stamp TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE network_members (
  node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('waiting', 'in', 'leaving')),
  address TEXT,
  port INTEGER NOT NULL,
  mtu INTEGER,
  uplink INTEGER,
  key TEXT NOT NULL,
  signer TEXT NOT NULL,
  endpoint TEXT,
  nat INTEGER NOT NULL DEFAULT 0,
  announce_key TEXT,
  announce_signature TEXT,
  points TEXT,
  since TEXT NOT NULL,
  joined_at TEXT
);

CREATE TABLE network_addresses (
  owner_user_id TEXT NOT NULL,
  address TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('used', 'held', 'freed')),
  node_id TEXT,
  node_name TEXT NOT NULL,
  freed_at TEXT,
  points TEXT,
  PRIMARY KEY (owner_user_id, address)
);

CREATE TABLE network_blocked (
  owner_user_id TEXT NOT NULL,
  key TEXT NOT NULL,
  node_id TEXT,
  at TEXT NOT NULL,
  PRIMARY KEY (owner_user_id, key)
);

CREATE TABLE network_links (
  a TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  b TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  answering INTEGER NOT NULL,
  since TEXT NOT NULL,
  PRIMARY KEY (a, b)
);

CREATE TABLE network_changes (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  at TEXT NOT NULL,
  change TEXT NOT NULL,
  detail TEXT,
  requested_by TEXT NOT NULL,
  device_id TEXT,
  nodes TEXT NOT NULL DEFAULT '[]',
  joins TEXT NOT NULL DEFAULT '[]',
  leaves TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX idx_network_changes_owner_at ON network_changes(owner_user_id, at);

ALTER TABLE nodes ADD COLUMN links TEXT;
