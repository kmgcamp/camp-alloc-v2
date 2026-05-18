-- migrations/0005_ddr_sites.sql
-- Add DDR Camp (36 rooms D1–D36) and DDR Caravan Park (50 rooms)
-- Run each statement separately in D1 Console
--
-- STATEMENT 1: DDR Camp site
INSERT OR IGNORE INTO sites (id, slug, name, room_count, is_active) VALUES
  (3, 'ddr-camp', 'DDR Camp', 36, 1);

-- STATEMENT 2: DDR Caravan Park site
INSERT OR IGNORE INTO sites (id, slug, name, room_count, is_active) VALUES
  (4, 'ddr-caravan', 'DDR Caravan Park', 50, 1);

-- STATEMENT 3: DDR Camp rooms D1–D36 (ids 201–236)
INSERT OR IGNORE INTO rooms (id, num, clean, repair, site_id) VALUES
  (201,'D1',1,0,3),(202,'D2',1,0,3),(203,'D3',1,0,3),(204,'D4',1,0,3),
  (205,'D5',1,0,3),(206,'D6',1,0,3),(207,'D7',1,0,3),(208,'D8',1,0,3),
  (209,'D9',1,0,3),(210,'D10',1,0,3),(211,'D11',1,0,3),(212,'D12',1,0,3),
  (213,'D13',1,0,3),(214,'D14',1,0,3),(215,'D15',1,0,3),(216,'D16',1,0,3),
  (217,'D17',1,0,3),(218,'D18',1,0,3),(219,'D19',1,0,3),(220,'D20',1,0,3),
  (221,'D21',1,0,3),(222,'D22',1,0,3),(223,'D23',1,0,3),(224,'D24',1,0,3),
  (225,'D25',1,0,3),(226,'D26',1,0,3),(227,'D27',1,0,3),(228,'D28',1,0,3),
  (229,'D29',1,0,3),(230,'D30',1,0,3),(231,'D31',1,0,3),(232,'D32',1,0,3),
  (233,'D33',1,0,3),(234,'D34',1,0,3),(235,'D35',1,0,3),(236,'D36',1,0,3);

-- STATEMENT 4: DDR Caravan Park — CP1–CP12 (ids 301–312)
INSERT OR IGNORE INTO rooms (id, num, clean, repair, site_id) VALUES
  (301,'CP1',1,0,4),(302,'CP2',1,0,4),(303,'CP3',1,0,4),(304,'CP4',1,0,4),
  (305,'CP5',1,0,4),(306,'CP6',1,0,4),(307,'CP7',1,0,4),(308,'CP8',1,0,4),
  (309,'CP9',1,0,4),(310,'CP10',1,0,4),(311,'CP11',1,0,4),(312,'CP12',1,0,4);

-- STATEMENT 5: DDR Caravan Park — P1–P16 (ids 313–328)
INSERT OR IGNORE INTO rooms (id, num, clean, repair, site_id) VALUES
  (313,'P1',1,0,4),(314,'P2',1,0,4),(315,'P3',1,0,4),(316,'P4',1,0,4),
  (317,'P5',1,0,4),(318,'P6',1,0,4),(319,'P7',1,0,4),(320,'P8',1,0,4),
  (321,'P9',1,0,4),(322,'P10',1,0,4),(323,'P11',1,0,4),(324,'P12',1,0,4),
  (325,'P13',1,0,4),(326,'P14',1,0,4),(327,'P15',1,0,4),(328,'P16',1,0,4);

-- STATEMENT 6: DDR Caravan Park — U1–U14 (ids 329–342)
INSERT OR IGNORE INTO rooms (id, num, clean, repair, site_id) VALUES
  (329,'U1',1,0,4),(330,'U2',1,0,4),(331,'U3',1,0,4),(332,'U4',1,0,4),
  (333,'U5',1,0,4),(334,'U6',1,0,4),(335,'U7',1,0,4),(336,'U8',1,0,4),
  (337,'U9',1,0,4),(338,'U10',1,0,4),(339,'U11',1,0,4),(340,'U12',1,0,4),
  (341,'U13',1,0,4),(342,'U14',1,0,4);

-- STATEMENT 7: DDR Caravan Park — R1–R8 (ids 343–350)
INSERT OR IGNORE INTO rooms (id, num, clean, repair, site_id) VALUES
  (343,'R1',1,0,4),(344,'R2',1,0,4),(345,'R3',1,0,4),(346,'R4',1,0,4),
  (347,'R5',1,0,4),(348,'R6',1,0,4),(349,'R7',1,0,4),(350,'R8',1,0,4);
