import type { NextApiRequest, NextApiResponse } from "next"
import { supabaseAdmin } from "@/lib/supabase"

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" })
  }

  const groupId = req.query.groupId
  const id = Array.isArray(groupId) ? groupId[0] : groupId

  if (!id) {
    return res.status(400).json({ error: "Missing group id" })
  }

  const { data: group, error: groupError } = await supabaseAdmin
    .from("chat_groups")
    .select("id, name")
    .eq("id", id)
    .maybeSingle()

  if (groupError) {
    return res.status(500).json({ error: groupError.message })
  }

  if (!group) {
    return res.status(404).json({ error: "Group not found" })
  }

  const [{ error: messagesError }, { error: deleteGroupError }] = await Promise.all([
    supabaseAdmin.from("chat_messages").delete().eq("group_id", id),
    supabaseAdmin.from("chat_groups").delete().eq("id", id),
  ])

  if (messagesError || deleteGroupError) {
    return res.status(500).json({ error: messagesError?.message || deleteGroupError?.message })
  }

  return res.status(200).json({ message: "Deleted", groupId: id, groupName: group.name })
}