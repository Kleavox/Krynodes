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
  last_seen_at TEXT,
  kind TEXT NOT NULL DEFAULT 'server' CHECK (kind IN ('server', 'laptop'))
);

CREATE TABLE enrollments (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  trust TEXT NOT NULL CHECK (json_valid(trust)),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  node_id TEXT,
  kind TEXT NOT NULL DEFAULT 'server' CHECK (kind IN ('server', 'laptop'))
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

CREATE TABLE network (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  cidr TEXT NOT NULL,
  port INTEGER NOT NULL,
  mtu INTEGER NOT NULL,
  version INTEGER NOT NULL,
  dns TEXT CHECK (dns IS NULL OR json_valid(dns)),
  deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
  created_at TEXT NOT NULL
);

CREATE TABLE network_documents (
  version INTEGER PRIMARY KEY,
  signed TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE network_members (
  node_id TEXT PRIMARY KEY REFERENCES nodes (id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('requested', 'rejected', 'in', 'leaving')),
  key TEXT,
  signer TEXT,
  ready INTEGER NOT NULL DEFAULT 0 CHECK (ready IN (0, 1)),
  reason TEXT,
  address TEXT,
  port INTEGER,
  mtu INTEGER,
  endpoint TEXT,
  nat INTEGER NOT NULL DEFAULT 0 CHECK (nat IN (0, 1)),
  applied INTEGER NOT NULL DEFAULT 0,
  failure TEXT,
  announce_key TEXT,
  announce_signature TEXT,
  since TEXT NOT NULL,
  joined_at TEXT
);

CREATE TABLE network_addresses (
  address TEXT PRIMARY KEY,
  node_id TEXT REFERENCES nodes (id) ON DELETE CASCADE,
  freed_at TEXT
);

CREATE TABLE network_blocked (
  key TEXT PRIMARY KEY,
  node_id TEXT REFERENCES nodes (id) ON DELETE SET NULL,
  at TEXT NOT NULL
);

CREATE TABLE network_links (
  a TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  b TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  answering INTEGER NOT NULL CHECK (answering IN (0, 1)),
  ms REAL,
  since TEXT NOT NULL,
  PRIMARY KEY (a, b)
);

CREATE TABLE network_changes (
  id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  change TEXT NOT NULL,
  detail TEXT,
  nodes TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(nodes))
);

CREATE INDEX network_changes_at ON network_changes (at DESC);
