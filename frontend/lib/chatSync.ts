import type { ChatMessage } from "./secureChatStore"

function resolveRelayUrl() {
  if (typeof window === "undefined") {
    return process.env.NEXT_PUBLIC_CHAT_RELAY_URL || "ws://localhost:8787"
  }

  if (process.env.NEXT_PUBLIC_CHAT_RELAY_URL) {
    return process.env.NEXT_PUBLIC_CHAT_RELAY_URL
  }

  // Default to same network host where frontend is opened.
  return `ws://${window.location.hostname}:8787`
}

type SnapshotMessage = {
  type: "snapshot"
  senderId: string
  payload: string
  sentAt: number
}

type RequestSnapshotMessage = {
  type: "request_snapshot"
  senderId: string
  sentAt: number
}

type HelloMessage = {
  type: "hello"
  senderId: string
  sentAt: number
}

type MessagePacket = {
  type: "message"
  senderId: string
  message: ChatMessage
  sentAt: number
}

type SyncMessage = SnapshotMessage | RequestSnapshotMessage | HelloMessage | MessagePacket

type SyncHandlers = {
  onSnapshot: (serializedState: string) => void
  onMessage?: (message: ChatMessage) => void
  onStatus?: (status: string) => void
  getSnapshot?: () => string | null
}

function makeClientId() {
  if (typeof window === "undefined") return "server"
  const arr = new Uint8Array(4)
  window.crypto.getRandomValues(arr)
  return `client-${Array.from(arr).map((x) => x.toString(16).padStart(2, "0")).join("")}`
}

export function createChatSyncClient(handlers: SyncHandlers) {
  const clientId = makeClientId()
  const relayUrl = resolveRelayUrl()
  let socket: WebSocket | null = null
  let channel: BroadcastChannel | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let disposed = false
  let initialized = false
  let lastAppliedPayload: string | null = null

  const emitRaw = (raw: string) => {
    console.log('[chatSync] emit raw', raw.slice(0, 120))
    try {
      channel?.postMessage(raw)
    } catch {
      // ignore
    }

    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(raw)
    }

    try {
      window.localStorage.setItem("secure_chat_sync_snapshot", raw)
    } catch {
      // ignore
    }
  }

  const emitControl = (type: "hello" | "request_snapshot") => {
    if (typeof window === "undefined") return
    const msg: HelloMessage | RequestSnapshotMessage = {
      type,
      senderId: clientId,
      sentAt: Date.now(),
    }
    emitRaw(JSON.stringify(msg))
  }

  const parseAndHandle = (raw: string) => {
    try {
      const msg = JSON.parse(raw) as SyncMessage
      if (msg.senderId === clientId) return

      if (msg.type === "hello") {
        return
      }

      if (msg.type === "request_snapshot") {
        const payload = handlers.getSnapshot?.()
        if (payload) {
          publishSnapshot(payload)
        }
        return
      }

      if (msg.type === "message") {
        handlers.onMessage?.(msg.message)
        return
      }

      if (msg.type === "snapshot") {
        console.log('[chatSync] received snapshot', msg.senderId, msg.payload?.slice(0, 80))
        if (!msg.payload) return
        if (msg.payload === lastAppliedPayload) return
        lastAppliedPayload = msg.payload
        handlers.onSnapshot(msg.payload)
      }
    } catch {
      // Ignore malformed sync packets
    }
  }

  const connectSocket = () => {
    if (typeof window === "undefined" || disposed) return

    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return
    }

    try {
      socket = new WebSocket(relayUrl)
      socket.onopen = () => {
        handlers.onStatus?.(`Connected to relay ${relayUrl}`)
        emitControl("hello")
        emitControl("request_snapshot")
        const payload = handlers.getSnapshot?.()
        if (payload) {
          setTimeout(() => {
            if (socket && socket.readyState === WebSocket.OPEN) {
              publishSnapshot(payload)
            }
          }, 250)
        }
        setTimeout(() => {
          if (socket && socket.readyState === WebSocket.OPEN) {
            emitControl("request_snapshot")
          }
        }, 1000)
      }
      socket.onclose = () => {
        handlers.onStatus?.("Relay disconnected. Retrying...")
        if (!disposed) {
          reconnectTimer = setTimeout(connectSocket, 2000)
        }
      }
      socket.onerror = () => {
        handlers.onStatus?.("Relay unavailable. Retrying...")
      }
      socket.onmessage = (ev) => {
        if (typeof ev.data === "string") parseAndHandle(ev.data)
      }
    } catch {
      handlers.onStatus?.("WebSocket init failed. Retrying...")
      if (!disposed) {
        reconnectTimer = setTimeout(connectSocket, 2000)
      }
    }
  }

  const connect = () => {
    if (typeof window === "undefined" || initialized) return
    initialized = true

    try {
      channel = new BroadcastChannel("secure-chat-sync")
      channel.onmessage = (ev) => {
        if (typeof ev.data === "string") parseAndHandle(ev.data)
      }
    } catch {
      handlers.onStatus?.("BroadcastChannel unavailable, using WebSocket/local only.")
    }

    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
      handlers.onStatus?.("Using localhost relay. For LAN sync, open app with host IP or set NEXT_PUBLIC_CHAT_RELAY_URL.")
    }

    window.addEventListener("storage", storageListener)
    connectSocket()
  }

  const storageListener = (event: StorageEvent) => {
    if (event.key !== "secure_chat_sync_snapshot") return
    if (!event.newValue) return
    parseAndHandle(event.newValue)
  }

  const publishSnapshot = (serializedState: string) => {
    if (typeof window === "undefined") return
    const packet: SnapshotMessage = {
      type: "snapshot",
      senderId: clientId,
      payload: serializedState,
      sentAt: Date.now(),
    }
    const raw = JSON.stringify(packet)
    lastAppliedPayload = serializedState
    emitRaw(raw)
  }

  const publishMessage = (message: ChatMessage) => {
    if (typeof window === "undefined") return
    const packet: MessagePacket = {
      type: "message",
      senderId: clientId,
      message,
      sentAt: Date.now(),
    }
    const raw = JSON.stringify(packet)
    emitRaw(raw)
  }

  const disconnect = () => {
    disposed = true
    initialized = false
    if (typeof window === "undefined") return
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    window.removeEventListener("storage", storageListener)
    channel?.close()
    channel = null
    socket?.close()
    socket = null
  }

  return {
    connect,
    publishSnapshot,
    publishMessage,
    disconnect,
  }
}
