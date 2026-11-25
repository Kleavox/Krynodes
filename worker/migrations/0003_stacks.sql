CREATE TABLE node_inventory (
  node_id TEXT PRIMARY KEY REFERENCES nodes (id) ON DELETE CASCADE,
  hash TEXT NOT NULL,
  body TEXT NOT NULL CHECK (json_valid(body)),
  updated_at TEXT NOT NULL
);

CREATE TABLE checks (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  container TEXT NOT NULL,
  name TEXT NOT NULL,
  public INTEGER NOT NULL DEFAULT 0,
  note TEXT,
  state TEXT NOT NULL DEFAULT 'unknown' CHECK (state IN ('unknown', 'up', 'down', 'gone')),
  cause TEXT,
  since TEXT,
  mailed_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (node_id, container)
);

CREATE TABLE check_transitions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  check_id TEXT NOT NULL REFERENCES checks (id) ON DELETE CASCADE,
  state TEXT NOT NULL,
  cause TEXT,
  at TEXT NOT NULL
);

CREATE INDEX check_transitions_check_at ON check_transitions (check_id, at);

ALTER TABLE nodes ADD COLUMN offline_mailed_at TEXT;
