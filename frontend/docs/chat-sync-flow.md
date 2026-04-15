# Chat Sync Flow (LAN + Offline)

This app uses an offline-first state with optional LAN WebSocket relay.

## Message Types

- `hello`: announces that a peer joined.
- `request_snapshot`: asks connected peers for latest chat state.
- `snapshot`: serialized secure chat state payload.

## Runtime Flow

1. Page loads local state from `localStorage`.
2. Sync client connects:
   - `BroadcastChannel` for same-browser contexts
   - `WebSocket` for same-network devices via relay
   - `storage` event fallback for cross-tab updates
3. On websocket open, client emits:
   - `hello`
   - `request_snapshot`
4. Any peer receiving `request_snapshot` responds with current `snapshot`.
5. Receiver applies newest snapshot only (`sentAt` ordering), then updates UI.
6. Local state changes publish a fresh `snapshot`.

## Why this works without DB

- Every client keeps full encrypted state locally.
- Relay only forwards packets in memory and stores nothing.
- If relay goes down, local/offline mode still works.

## Start Relay

```bash
npm run relay:chat
```

Optional environment:

- `CHAT_RELAY_HOST` default: `0.0.0.0`
- `CHAT_RELAY_PORT` default: `8787`
- `NEXT_PUBLIC_CHAT_RELAY_URL` client default: `ws://localhost:8787`
