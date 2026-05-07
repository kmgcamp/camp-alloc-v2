-- migrations/0001_init.sql
-- Complete initial schema for camp-alloc-v2
-- Run each statement separately in D1 Console
--
-- STATEMENT 1: rooms table
CREATE TABLE IF NOT EXISTS rooms (
  id      INTEGER PRIMARY KEY,
  num     TEXT    NOT NULL,
  clean   INTEGER NOT NULL DEFAULT 1,
  repair  INTEGER NOT NULL DEFAULT 0
);

-- STATEMENT 2: bookings table
CREATE TABLE IF NOT EXISTS bookings (
  id             TEXT    PRIMARY KEY,
  room_id        INTEGER NOT NULL REFERENCES rooms(id),
  name           TEXT    NOT NULL,
  company        TEXT    DEFAULT '',
  role           TEXT    DEFAULT '',
  checkin        TEXT    NOT NULL,
  checkout       TEXT    NOT NULL,
  clean          INTEGER NOT NULL DEFAULT 1,
  repair         INTEGER NOT NULL DEFAULT 0,
  notes          TEXT    DEFAULT '',
  color          INTEGER NOT NULL DEFAULT 0,
  roster_pattern TEXT    DEFAULT '',
  offweek        TEXT    NOT NULL DEFAULT 'held'
);

-- STATEMENT 3: booking_segments table
CREATE TABLE IF NOT EXISTS booking_segments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  booking_id TEXT    NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
  checkin    TEXT    NOT NULL,
  checkout   TEXT    NOT NULL,
  is_on      INTEGER NOT NULL DEFAULT 1
);

-- STATEMENT 4: Seed rooms R01–R80
INSERT OR IGNORE INTO rooms (id, num, clean, repair) VALUES
(1,'R01',1,0),(2,'R02',1,0),(3,'R03',1,0),(4,'R04',1,0),(5,'R05',1,0),
(6,'R06',1,0),(7,'R07',1,0),(8,'R08',1,0),(9,'R09',1,0),(10,'R10',1,0),
(11,'R11',1,0),(12,'R12',1,0),(13,'R13',1,0),(14,'R14',1,0),(15,'R15',1,0),
(16,'R16',1,0),(17,'R17',1,0),(18,'R18',1,0),(19,'R19',1,0),(20,'R20',1,0),
(21,'R21',1,0),(22,'R22',1,0),(23,'R23',1,0),(24,'R24',1,0),(25,'R25',1,0),
(26,'R26',1,0),(27,'R27',1,0),(28,'R28',1,0),(29,'R29',1,0),(30,'R30',1,0),
(31,'R31',1,0),(32,'R32',1,0),(33,'R33',1,0),(34,'R34',1,0),(35,'R35',1,0),
(36,'R36',1,0),(37,'R37',1,0),(38,'R38',1,0),(39,'R39',1,0),(40,'R40',1,0),
(41,'R41',1,0),(42,'R42',1,0),(43,'R43',1,0),(44,'R44',1,0),(45,'R45',1,0),
(46,'R46',1,0),(47,'R47',1,0),(48,'R48',1,0),(49,'R49',1,0),(50,'R50',1,0),
(51,'R51',1,0),(52,'R52',1,0),(53,'R53',1,0),(54,'R54',1,0),(55,'R55',1,0),
(56,'R56',1,0),(57,'R57',1,0),(58,'R58',1,0),(59,'R59',1,0),(60,'R60',1,0),
(61,'R61',1,0),(62,'R62',1,0),(63,'R63',1,0),(64,'R64',1,0),(65,'R65',1,0),
(66,'R66',1,0),(67,'R67',1,0),(68,'R68',1,0),(69,'R69',1,0),(70,'R70',1,0),
(71,'R71',1,0),(72,'R72',1,0),(73,'R73',1,0),(74,'R74',1,0),(75,'R75',1,0),
(76,'R76',1,0),(77,'R77',1,0),(78,'R78',1,0),(79,'R79',1,0),(80,'R80',1,0);

-- STATEMENT 5: Add rooms R81–R83
INSERT OR IGNORE INTO rooms (id, num, clean, repair) VALUES
(81,'R81',1,0),(82,'R82',1,0),(83,'R83',1,0);
