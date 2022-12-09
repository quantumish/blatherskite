CREATE TABLE users (
  id BIGINT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  hash TEXT NOT NULL
);

CREATE TABLE groups (
  id BIGINT PRIMARY KEY,
  name TEXT NOT NULL,
  members BIGINT[] NOT NULL,
  is_dm BOOLEAN NOT NULL,
  channels BIGINT[] NOT NULL,
  admin BIGINT[] NOT NULL,
  owner BIGINT NOT NULL
);

CREATE TABLE channels (
  id BIGINT PRIMARY KEY,
  src_group BIGINT NOT NULL,
  name TEXT NOT NULL,
  members BIGINT[] NOT NULL,
  private BOOLEAN NOT NULL
);

CREATE TABLE user_groups (
  id BIGINT PRIMARY KEY,
  groups BIGINT[] NOT NULL
);

CREATE TABLE user_dms (
  id BIGINT PRIMARY KEY,
  dms BIGINT[] NOT NULL
);

CREATE TABLE messages (
  channel BIGINT PRIMARY KEY,
  id BIGINT NOT NULL,
  author BIGINT NOT NULL,
  content TEXT 
  thread BIGINT
);
