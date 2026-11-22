CREATE TABLE nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  agent_token_hash TEXT NOT NULL UNIQUE,
  enrolled_at TEXT NOT NULL,
  hostname TEXT,
  os TEXT,
  arch TEXT,
  kernel TEXT,
  version TEXT,
  seal_key TEXT,
  last_seen_at TEXT
);

CREATE TABLE enrollments (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  trust TEXT NOT NULL CHECK (json_valid(trust)),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  node_id TEXT
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  alg TEXT NOT NULL,
  public_key TEXT NOT NULL,
  synced INTEGER NOT NULL DEFAULT 0 CHECK (synced IN (0, 1)),
  created_at TEXT NOT NULL
);

CREATE TABLE node_trust (
  node_id TEXT PRIMARY KEY REFERENCES nodes (id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  core TEXT NOT NULL CHECK (json_valid(core)),
  access TEXT NOT NULL CHECK (json_valid(access)),
  reported_at TEXT NOT NULL
);

CREATE TABLE actions (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  action TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('sent', 'running', 'done', 'failed')),
  message TEXT,
  output TEXT,
  created_at TEXT NOT NULL,
  finished_at TEXT
);

CREATE INDEX actions_node_created ON actions (node_id, created_at DESC);

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE agent_release (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version TEXT NOT NULL,
  checked_at TEXT NOT NULL
);
