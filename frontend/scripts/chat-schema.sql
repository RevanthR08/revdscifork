-- Supabase Chat Backend Schema

-- Users table for chat identities
CREATE TABLE IF NOT EXISTS chat_users (
  id text PRIMARY KEY,
  name text NOT NULL,
  color text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  inserted_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Groups table for chat rooms
CREATE TABLE IF NOT EXISTS chat_groups (
  id text PRIMARY KEY,
  name text NOT NULL,
  members jsonb NOT NULL DEFAULT '[]'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  pinned_message_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE IF EXISTS chat_groups
  ADD COLUMN IF NOT EXISTS pinned_message_ids jsonb NOT NULL DEFAULT '[]'::jsonb;

-- Messages table for chat history
CREATE TABLE IF NOT EXISTS chat_messages (
  id text PRIMARY KEY,
  group_id text NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  sender_id text NOT NULL REFERENCES chat_users(id) ON DELETE SET NULL,
  envelope jsonb NOT NULL,
  signature_b64 text NOT NULL,
  reply_to_message_id text REFERENCES chat_messages(id) ON DELETE SET NULL,
  reactions jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  sent_at timestamptz NOT NULL,
  inserted_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS chat_messages_group_sent_at_idx ON chat_messages (group_id, sent_at ASC);
