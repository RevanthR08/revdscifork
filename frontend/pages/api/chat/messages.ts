import type { ChatMessage } from "@/lib/secureChatStore"
import type { NextApiRequest, NextApiResponse } from "next"
import { supabaseAdmin, isSupabaseConfigured } from "@/lib/supabase"

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

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    if (!isSupabaseConfigured) {
      return res.status(200).json({ messages: [], mockMode: true })
    }
    const groupId = req.query.groupId as string | undefined
    let query = supabaseAdmin.from("chat_messages").select("*").order("sent_at", { ascending: true })
    if (groupId) {
      query = query.eq("group_id", groupId)
    }

    const { data, error } = await query
    if (error) {
      return res.status(500).json({ error: error.message })
    }

    return res.status(200).json({ messages: (data || []).map((message) => camelizeObject(message)) })
  }

  if (req.method === "POST") {
    if (!isSupabaseConfigured) {
      return res.status(201).json({ message: "ok (Mock Mode)" })
    }
    const message = req.body.message as ChatMessage | undefined
    if (!message || !message.id) {
      return res.status(400).json({ error: "Invalid message payload" })
    }

    const messageForDb = snakeCaseObject(message)
    messageForDb.sent_at = typeof message.sentAt === "number" ? new Date(message.sentAt).toISOString() : message.sentAt

    const { data: group, error: groupError } = await supabaseAdmin
      .from("chat_groups")
      .select("id")
      .eq("id", message.groupId)
      .maybeSingle()

    if (groupError) {
      return res.status(500).json({ error: groupError.message })
    }

    if (!group) {
      return res.status(400).json({ error: "Group not found. Create or sync group state first." })
    }

    const { error: messageError } = await supabaseAdmin.from("chat_messages").insert([messageForDb])

    if (messageError) {
      return res.status(500).json({ error: messageError.message })
    }

    return res.status(201).json({ message: "ok" })
  }

  return res.status(405).json({ error: "Method not allowed" })
}
