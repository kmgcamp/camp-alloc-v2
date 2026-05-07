-- migrations/0004_multi_site.sql
-- Add multi-site support: sites table + site_id on rooms
--
-- Run each statement separately in the D1 console.
--
-- STATEMENT 1: Create sites table
CREATE TABLE IF NOT EXISTS sites (
  id         INTEGER PRIMARY KEY,
  slug       TEXT    NOT NULL UNIQUE,  -- e.g. 'kununurra', 'wyndham'
  name       TEXT    NOT NULL,         -- display name
  room_count INTEGER NOT NULL DEFAULT 0,
  is_active  INTEGER NOT NULL DEFAULT 1
);

-- STATEMENT 2: Seed the two sites
INSERT OR IGNORE INTO sites (id, slug, name, room_count) VALUES
  (1, 'kununurra', 'Kununurra Camp',       83),
  (2, 'wyndham',   'Wyndham Airport Camp', 16);

-- STATEMENT 3: Add site_id column to rooms (defaults to 1 = Kununurra)
ALTER TABLE rooms ADD COLUMN site_id INTEGER NOT NULL DEFAULT 1 REFERENCES sites(id);

-- STATEMENT 4: Seed Wyndham rooms W01–W16
INSERT OR IGNORE INTO rooms (id, num, clean, repair, site_id) VALUES
  (84, 'W01', 1, 0, 2),
  (85, 'W02', 1, 0, 2),
  (86, 'W03', 1, 0, 2),
  (87, 'W04', 1, 0, 2),
  (88, 'W05', 1, 0, 2),
  (89, 'W06', 1, 0, 2),
  (90, 'W07', 1, 0, 2),
  (91, 'W08', 1, 0, 2),
  (92, 'W09', 1, 0, 2),
  (93, 'W10', 1, 0, 2),
  (94, 'W11', 1, 0, 2),
  (95, 'W12', 1, 0, 2),
  (96, 'W13', 1, 0, 2),
  (97, 'W14', 1, 0, 2),
  (98, 'W15', 1, 0, 2),
  (99, 'W16', 1, 0, 2);
