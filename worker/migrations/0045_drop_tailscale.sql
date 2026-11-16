DROP INDEX idx_tailscale_tailnet;
DROP INDEX idx_tailscale_alarms_owner;

DROP TABLE tailscale_alarms;
DROP TABLE tailscale_nodes;
DROP TABLE tailscale;

ALTER TABLE nodes DROP COLUMN tailscale;
ALTER TABLE nodes DROP COLUMN tailscale_vault;
