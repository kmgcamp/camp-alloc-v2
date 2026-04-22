-- migrations/0002_add_rooms_81_83.sql
-- Add rooms R81, R82, R83 to bring total from 80 to 83

INSERT OR IGNORE INTO rooms (id, num, clean, repair) VALUES
(81, 'R81', 1, 0),
(82, 'R82', 1, 0),
(83, 'R83', 1, 0);
