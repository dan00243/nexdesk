-- NexDesk — PostgreSQL Schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

DO $$ BEGIN
  CREATE TYPE device_status   AS ENUM ('active','banned','pending');
  CREATE TYPE device_platform AS ENUM ('windows','macos','linux','android','ios');
  CREATE TYPE session_status  AS ENUM ('pending','active','ended','rejected','timeout');
  CREATE TYPE end_reason      AS ENUM ('normal','host_left','ctrl_left','kicked','timeout','error');
EXCEPTION WHEN duplicate_object THEN null; END $$;

CREATE TABLE IF NOT EXISTS devices (
  id               VARCHAR(11)     PRIMARY KEY,
  name             VARCHAR(100)    NOT NULL DEFAULT '',
  platform         device_platform NOT NULL,
  os_version       VARCHAR(50),
  app_version      VARCHAR(20),
  status           device_status   NOT NULL DEFAULT 'active',
  public_key       TEXT,
  temp_pw_hash     VARCHAR(200),
  temp_pw_exp      TIMESTAMPTZ,
  perm_pw_hash     VARCHAR(200),
  totp_secret      VARCHAR(64),
  allow_unattended BOOLEAN NOT NULL DEFAULT FALSE,
  last_ip          VARCHAR(45),
  last_seen        TIMESTAMPTZ,
  online           BOOLEAN NOT NULL DEFAULT FALSE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  extra            JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_dev_status  ON devices(status);
CREATE INDEX IF NOT EXISTS ix_dev_online  ON devices(online);

CREATE TABLE IF NOT EXISTS whitelist (
  id                SERIAL PRIMARY KEY,
  device_id         VARCHAR(11) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  trusted_device_id VARCHAR(11) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  label             VARCHAR(100),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at        TIMESTAMPTZ,
  UNIQUE(device_id, trusted_device_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  status        session_status NOT NULL DEFAULT 'pending',
  host_id       VARCHAR(11) REFERENCES devices(id) ON DELETE SET NULL,
  controller_id VARCHAR(11) REFERENCES devices(id) ON DELETE SET NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at    TIMESTAMPTZ,
  ended_at      TIMESTAMPTZ,
  duration_s    INTEGER,
  view_only     BOOLEAN NOT NULL DEFAULT FALSE,
  allow_files   BOOLEAN NOT NULL DEFAULT TRUE,
  allow_chat    BOOLEAN NOT NULL DEFAULT TRUE,
  quality       VARCHAR(20) NOT NULL DEFAULT 'balanced',
  bytes_sent    BIGINT NOT NULL DEFAULT 0,
  bytes_recv    BIGINT NOT NULL DEFAULT 0,
  avg_latency   FLOAT,
  avg_fps       FLOAT,
  end_reason    end_reason,
  error_msg     TEXT
);
CREATE INDEX IF NOT EXISTS ix_ses_host   ON sessions(host_id);
CREATE INDEX IF NOT EXISTS ix_ses_status ON sessions(status);
CREATE INDEX IF NOT EXISTS ix_ses_start  ON sessions(started_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
  id         SERIAL PRIMARY KEY,
  session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
  device_id  VARCHAR(11) REFERENCES devices(id) ON DELETE SET NULL,
  timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event_type VARCHAR(50) NOT NULL,
  detail     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_audit_ses ON audit_events(session_id);
CREATE INDEX IF NOT EXISTS ix_audit_ts  ON audit_events(timestamp DESC);

CREATE TABLE IF NOT EXISTS file_transfers (
  id           SERIAL PRIMARY KEY,
  session_id   UUID REFERENCES sessions(id) ON DELETE CASCADE,
  sender_id    VARCHAR(11) REFERENCES devices(id) ON DELETE SET NULL,
  filename     VARCHAR(255) NOT NULL,
  mime_type    VARCHAR(100),
  size_bytes   BIGINT,
  sha256       VARCHAR(64),
  status       VARCHAR(20) NOT NULL DEFAULT 'pending',
  started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  storage_path TEXT
);

-- Auto-compute duration
CREATE OR REPLACE FUNCTION set_session_duration()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.ended_at IS NOT NULL AND NEW.started_at IS NOT NULL THEN
    NEW.duration_s := EXTRACT(EPOCH FROM (NEW.ended_at - NEW.started_at))::INTEGER;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_duration ON sessions;
CREATE TRIGGER trg_duration BEFORE UPDATE ON sessions
  FOR EACH ROW WHEN (NEW.ended_at IS DISTINCT FROM OLD.ended_at)
  EXECUTE FUNCTION set_session_duration();
