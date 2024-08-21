CREATE KEYSPACE IF NOT EXISTS xgdb
  WITH REPLICATION = {
    'class' : 'SimpleStrategy',
    'replication_factor' : 1
  };

CREATE TABLE IF NOT EXISTS xgdb.auth (
  login text,
  passwordhash text,
  groups text,
  PRIMARY KEY (login)
);

CREATE INDEX IF NOT EXISTS IX_xgdb_passwordhash
    ON xgdb.auth ( passwordhash );

INSERT INTO xgdb.auth (login, passwordhash) VALUES ('admin', '2f88ecf29ab10ecaaf0a850ff0bf88c0899af1c40dc941fed808ff14b2e6ad556f144159cec7da63921e1141aecedc223e6a38d1d479a05af6af3f902e8ed197') IF NOT EXISTS;