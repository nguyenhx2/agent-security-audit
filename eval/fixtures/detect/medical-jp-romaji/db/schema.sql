CREATE TABLE kanja (
  kanja_id integer PRIMARY KEY,
  shimei text
);
CREATE TABLE karte (
  karte_id integer PRIMARY KEY,
  kanja_id integer
);
