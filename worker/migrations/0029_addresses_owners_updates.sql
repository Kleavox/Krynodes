ALTER TABLE nodes ADD COLUMN ipv4 TEXT;
ALTER TABLE nodes ADD COLUMN ipv4_at TEXT;
ALTER TABLE nodes ADD COLUMN ipv6 TEXT;
ALTER TABLE nodes ADD COLUMN ipv6_at TEXT;

ALTER TABLE devices ADD COLUMN account TEXT;

UPDATE devices SET account = (
  SELECT requested_by FROM actions
  WHERE actions.device_id = devices.id
  ORDER BY requested_at DESC
  LIMIT 1
);

CREATE TABLE incident_updates (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('investigating', 'identified', 'monitoring', 'update')),
  message TEXT NOT NULL,
  author TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_incident_updates_incident ON incident_updates(incident_id, created_at);
