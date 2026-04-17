import type { NextApiRequest, NextApiResponse } from "next"
import { supabaseAdmin, isSupabaseConfigured } from "@/lib/supabase"

const DEFAULT_USERS = [
  { id: "u-admin", name: "Security Admin", color: "bg-violet-500/30 text-violet-300", metadata: {} },
  { id: "u-user", name: "SOC Analyst", color: "bg-sky-500/30 text-sky-300", metadata: {} },
]

const DEFAULT_GROUPS = [
  {
    id: "grp-admin-user",
    name: "Admin & SOC",
    members: ["u-admin", "u-user"],
    metadata: {
      ownerUserId: "u-admin",
      createdAt: Date.now(),
      classification: "confidential",
      tags: [],
      attackChains: [],
      reportDetails: [],
    },
    pinnedMessageIds: [],
  },
]

function camelize(str: string) {
  return str.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())
}

function camelizeObject<T = Record<string, any>>(value: unknown): T {
  if (Array.isArray(value)) {
    return value.map((item) => camelizeObject(item)) as unknown as T
  }

  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).reduce((result, [key, val]) => {
      const camelKey = camelize(key)
      const normalized = camelizeObject(val)
      result[camelKey] = camelKey === "sentAt" && typeof normalized === "string" ? Date.parse(normalized) : normalized
      return result
    }, {} as Record<string, unknown>) as T
  }

  return value as T
}

function snakeCase(str: string) {
  return str.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)
}

function snakeCaseObject<T = Record<string, any>>(value: unknown): T {
  if (Array.isArray(value)) {
    return value.map((item) => snakeCaseObject(item)) as unknown as T
  }

  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).reduce((result, [key, val]) => {
      result[snakeCase(key)] = snakeCaseObject(val)
      return result
    }, {} as Record<string, unknown>) as T
  }

  return value as T
}

function normalizeMessageForDb(message: Record<string, any>) {
  const normalized = snakeCaseObject(message)
  normalized.sent_at = typeof message.sentAt === "number" ? new Date(message.sentAt).toISOString() : message.sentAt
  return normalized
}

async function ensureSeedState() {
  const now = new Date().toISOString()
  const users = DEFAULT_USERS.map((user) => ({ ...user, inserted_at: now, updated_at: now }))
  const groups = DEFAULT_GROUPS.map((group) => ({ ...group, created_at: now, updated_at: now }))

  await Promise.all([
    supabaseAdmin.from("chat_users").upsert(users, { onConflict: "id" }),
    supabaseAdmin.from("chat_groups").upsert(groups, { onConflict: "id" }),
  ])
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    if (!isSupabaseConfigured) {
      return res.status(503).json({ error: "Supabase unconfigured, falling back to local state." })
    }
    await ensureSeedState()


    const [{ data: users, error: usersError }, { data: groups, error: groupsError }, { data: messages, error: messagesError }] =
      await Promise.all([
        supabaseAdmin.from("chat_users").select("*"),
        supabaseAdmin.from("chat_groups").select("*").order("created_at", { ascending: true }),
        supabaseAdmin.from("chat_messages").select("*").order("sent_at", { ascending: true }),
      ])

    if (usersError || groupsError || messagesError) {
      return res.status(500).json({
        error: usersError?.message || groupsError?.message || messagesError?.message,
      })
    }

    return res.status(200).json({
      users: (users || []).map((user) => camelizeObject(user)),
      groups: (groups || []).map((group) => camelizeObject(group)),
      messages: (messages || []).map((message) => camelizeObject(message)),
      selectedGroupId: (groups && groups[0]?.id) || "",
    })
  }

  if (req.method === "POST") {
    if (!isSupabaseConfigured) {
      return res.status(200).json({ message: "State saved locally (Mock Mode)" })
    }
    const state = req.body as {
      users?: Record<string, any>[]
      groups?: Record<string, any>[]
      messages?: Record<string, any>[]
    }

    if (!state.users || !state.groups) {
      return res.status(400).json({ error: "Invalid state payload" })
    }

    const now = new Date().toISOString()
    const usersForDb = state.users.map((user) => ({ ...snakeCaseObject(user), inserted_at: now, updated_at: now }))
    const groupsForDb = state.groups.map((group) => ({ ...snakeCaseObject(group), created_at: now, updated_at: now }))
    const messagesForDb = (state.messages || []).map(normalizeMessageForDb)

    const [{ error: usersError }, { error: groupsError }, { error: messagesError }] = await Promise.all([
      supabaseAdmin.from("chat_users").upsert(usersForDb, { onConflict: "id" }),
      supabaseAdmin.from("chat_groups").upsert(groupsForDb, { onConflict: "id" }),
      supabaseAdmin.from("chat_messages").upsert(messagesForDb, { onConflict: "id" }),
    ])

    if (usersError || groupsError || messagesError) {
      return res.status(500).json({
        error: usersError?.message || groupsError?.message || messagesError?.message,
      })
    }

    return res.status(200).json({ message: "State saved" })
  }

  return res.status(405).json({ error: "Method not allowed" })
}
