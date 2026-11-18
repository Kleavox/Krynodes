ALTER TABLE nodes ADD COLUMN kind TEXT NOT NULL DEFAULT 'server' CHECK (kind IN ('server','laptop'));
ALTER TABLE network_changes ADD COLUMN kind TEXT CHECK (kind IN ('laptop.add','laptop.remove','network.exit'));
