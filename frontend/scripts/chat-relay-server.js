/*
  Simple LAN WebSocket relay for secure chat snapshots.
  - No database
  - Forwards packets between clients on same network
  - Intended for local/private network usage
*/

const { WebSocketServer } = require("ws")

const port = Number(process.env.CHAT_RELAY_PORT || 8787)
const host = process.env.CHAT_RELAY_HOST || "0.0.0.0"

const wss = new WebSocketServer({ port, host })

function safeParse(raw) {
  try {
    return JSON.parse(raw.toString())
  } catch {
    return null
  }
}

wss.on("connection", (socket, req) => {
  const remote = req.socket.remoteAddress || "unknown"
  console.log(`[relay] client connected from ${remote}`)

  socket.on("message", (raw) => {
    const packet = safeParse(raw)
    if (!packet || !packet.type || !packet.senderId) {
      return
    }

    // Fan-out relay: send message to every connected peer except sender.
    for (const client of wss.clients) {
      if (client !== socket && client.readyState === 1) {
        client.send(raw)
      }
    }
  })

  socket.on("close", () => {
    console.log(`[relay] client disconnected from ${remote}`)
  })
})

console.log(`[relay] secure chat relay listening on ws://${host}:${port}`)
