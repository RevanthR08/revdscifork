# Supabase Chat Schema

This backend schema stores chat state in Supabase and supports real-time message persistence.

## Environment Variables

Add these to `frontend/.env.local`:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key-here
```

> Use `SUPABASE_SERVICE_ROLE_KEY` only on the server. Do not expose it in client-side code.

## SQL Schema

```sql
-- Users table for chat identities
create table if not exists chat_users (
  id text primary key,
  name text not null,
  color text not null,
  metadata jsonb default '{}' not null,
  inserted_at timestamptz default now() not null,
  updated_at timestamptz default now() not null
);

-- Groups table for chat rooms
create table if not exists chat_groups (
  id text primary key,
  name text not null,
  members jsonb not null default '[]',
  metadata jsonb default '{}' not null,
  created_at timestamptz default now() not null,
  updated_at timestamptz default now() not null
);

-- Messages table for chat message history
create table if not exists chat_messages (
  id text primary key,
  group_id text not null references chat_groups(id) on delete cascade,
  sender_id text not null references chat_users(id) on delete set null,
  envelope jsonb not null,
  signature_b64 text not null,
  reply_to_message_id text references chat_messages(id) on delete set null,
  reactions jsonb not null default '{}'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  sent_at timestamptz not null,
  inserted_at timestamptz default now() not null,
  updated_at timestamptz default now() not null
);

-- Optional helper index for message ordering
create index if not exists chat_messages_group_sent_at_idx on chat_messages (group_id, sent_at asc);
```

## API Endpoints

- `GET /api/chat/state` — returns full chat state from Supabase
- `GET /api/chat/messages?groupId=...` — returns messages for a group
- `POST /api/chat/messages` — inserts a new chat message

## Notes

- The backend stores the full encrypted envelope and signature per message.
- The API is server-side only and uses the secure `SUPABASE_SERVICE_ROLE_KEY`.
- The frontend can call `/api/chat/messages` when a message is sent and `/api/chat/state` on page load.
