ALTER TABLE nodes ADD COLUMN interfaces TEXT;
ALTER TABLE nodes ADD COLUMN ipv4_network TEXT;
ALTER TABLE nodes ADD COLUMN ipv6_network TEXT;
ALTER TABLE nodes ADD COLUMN ipv4_owner TEXT CHECK (ipv4_owner IN ('own', 'router'));
ALTER TABLE nodes ADD COLUMN ipv6_owner TEXT CHECK (ipv6_owner IN ('own', 'router'));

DELETE FROM settings WHERE key = 'address_display';
