import React, { ChangeEvent, FormEvent, useEffect, useMemo, useState } from "react"
import DashboardLayout from "@/components/layout/DashboardLayout"
import { motion } from "framer-motion"
import {
  MessageCircle,
  GitBranch,
  Reply,
  Pin,
  SmilePlus,
  Image as ImageIcon,
  Video,
  FileText,
  ShieldCheck,
  ShieldAlert,
  Plus,
  X,
  Users,
  Send,
} from "lucide-react"
import { cn } from "@/lib/utils"
import {
  type ChatMessage,
  type ChatUser,
  type ChatGroup,
  type DecryptedMessage,
  type MediaAttachment,
  createGroup,
  createSignedMessage,
  getCurrentUserId,
  loadSecureChatState,
  saveSecureChatState,
  verifyAndDecryptMessage,
} from "@/lib/secureChatStore"

const CURRENT_USER = getCurrentUserId()
const EMOJIS = ["👍", "🔥", "✅", "🚨", "👀"]

function getSender(users: ChatUser[], id: string) {
  return users.find((u) => u.id === id)
}

export default function ChatPage() {
  const [users, setUsers] = useState<ChatUser[]>([])
  const [groups, setGroups] = useState<ChatGroup[]>([])
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [selectedGroupId, setSelectedGroupId] = useState<string>("")
  const [text, setText] = useState("")
  const [replyToMessageId, setReplyToMessageId] = useState<string | null>(null)
  const [attachment, setAttachment] = useState<MediaAttachment | undefined>(undefined)
  const [newGroupName, setNewGroupName] = useState("")
  const [newGroupMembers, setNewGroupMembers] = useState<string[]>([CURRENT_USER])
  const [createOpen, setCreateOpen] = useState(false)
  const [infoBanner, setInfoBanner] = useState<string>("")

  const selectedGroup = useMemo(
    () => groups.find((g) => g.id === selectedGroupId) ?? null,
    [groups, selectedGroupId]
  )

  const groupMessages = useMemo(() => {
    return messages
      .filter((m) => m.groupId === selectedGroupId)
      .sort((a, b) => a.sentAt - b.sentAt)
  }, [messages, selectedGroupId])

  const [decryptedById, setDecryptedById] = useState<Record<string, DecryptedMessage>>({})

  useEffect(() => {
    let mounted = true
    loadSecureChatState()
      .then((state) => {
        if (!mounted) return
        setUsers(state.users)
        setGroups(state.groups)
        setMessages(state.messages)
        setSelectedGroupId(state.selectedGroupId)
        setInfoBanner("Secure mode enabled: AES-GCM encryption + ECDSA signatures.")
      })
      .catch(() => {
      setInfoBanner("Secure chat initialization failed. Please refresh.")
    })

    return () => {
      mounted = false
    }
  }, [])

  useEffect(() => {
    if (!users.length || !groups.length) return
    saveSecureChatState({
      users,
      groups,
      messages,
      selectedGroupId,
    })
  }, [users, groups, messages, selectedGroupId])

  useEffect(() => {
    let active = true

    const decryptAll = async () => {
      if (!selectedGroup) {
        setDecryptedById({})
        return
      }

      const next: Record<string, DecryptedMessage> = {}
      for (const message of groupMessages) {
        try {
          const result = await verifyAndDecryptMessage({
            message,
            users,
            groups,
          })
          next[message.id] = result
        } catch {
          next[message.id] = { payload: null, tampered: true }
        }
      }

      if (active) {
        setDecryptedById(next)
      }
    }

    decryptAll().catch(() => {
      setInfoBanner("Failed to decrypt one or more messages.")
    })

    return () => {
      active = false
    }
  }, [groupMessages, selectedGroup, users])

  const handleCreateGroup = async (e: FormEvent) => {
    e.preventDefault()
    const cleanName = newGroupName.trim()
    if (!cleanName || newGroupMembers.length < 2) {
      setInfoBanner("Group needs a name and at least 2 members.")
      return
    }

    const group = await createGroup({
      name: cleanName,
      members: Array.from(new Set(newGroupMembers)),
      ownerUserId: CURRENT_USER,
    })

    setGroups((prev) => [group, ...prev])
    setSelectedGroupId(group.id)
    setNewGroupName("")
    setNewGroupMembers([CURRENT_USER])
    setCreateOpen(false)
    setInfoBanner(`Group ${cleanName} created with E2E key material.`)
  }

  const onPickMedia = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ""
    if (!file) return

    if (file.size > 2 * 1024 * 1024) {
      setInfoBanner("Media size limit is 2MB for this demo.")
      return
    }

    const reader = new FileReader()
    reader.onload = () => {
      const value = reader.result
      if (typeof value !== "string") return
      setAttachment({
        name: file.name,
        mimeType: file.type || "application/octet-stream",
        dataUrl: value,
      })
    }
    reader.readAsDataURL(file)
  }

  const handleSend = async (e: FormEvent) => {
    e.preventDefault()
    if (!selectedGroup) return
    if (!text.trim() && !attachment) return

    const me = users.find((u) => u.id === CURRENT_USER)
    if (!me) return

    const payload = {
      text: text.trim(),
      media: attachment,
    }

    const message = await createSignedMessage({
      group: selectedGroup,
      sender: me,
      payload,
      replyToMessageId: replyToMessageId ?? undefined,
    })

    setMessages((prev) => [...prev, message])
    setText("")
    setReplyToMessageId(null)
    setAttachment(undefined)
    setInfoBanner("Encrypted message sent and signature attached.")
  }

  const toggleReaction = (messageId: string, emoji: string) => {
    setMessages((prev) =>
      prev.map((m) => {
        if (m.id !== messageId) return m
        const existing = m.reactions[emoji] ?? []
        const hasMine = existing.includes(CURRENT_USER)
        return {
          ...m,
          reactions: {
            ...m.reactions,
            [emoji]: hasMine ? existing.filter((uid) => uid !== CURRENT_USER) : [...existing, CURRENT_USER],
          },
        }
      })
    )
  }

  const togglePin = (messageId: string) => {
    if (!selectedGroup) return

    setGroups((prev) =>
      prev.map((g) => {
        if (g.id !== selectedGroup.id) return g
        const exists = g.pinnedMessageIds.includes(messageId)
        return {
          ...g,
          pinnedMessageIds: exists ? g.pinnedMessageIds.filter((id) => id !== messageId) : [messageId, ...g.pinnedMessageIds],
        }
      })
    )
  }

  const pinnedMessages = useMemo(() => {
    if (!selectedGroup) return []
    const set = new Set(selectedGroup.pinnedMessageIds)
    return groupMessages.filter((m) => set.has(m.id))
  }, [groupMessages, selectedGroup])

  const replyMessage = useMemo(() => {
    if (!replyToMessageId) return null
    return groupMessages.find((m) => m.id === replyToMessageId) ?? null
  }, [groupMessages, replyToMessageId])

  const canRender = users.length > 0 && groups.length > 0

  const importedChains = useMemo(() => {
    if (!selectedGroup) return []
    return [...selectedGroup.metadata.attackChains].sort((a, b) => b.addedAt - a.addedAt)
  }, [selectedGroup])

  const importChainToComposer = (chainId: string) => {
    if (!selectedGroup) return
    const chain = selectedGroup.metadata.attackChains.find((item) => item.id === chainId)
    if (!chain) return

    const importText = [
      `Imported Attack Chain: ${chain.title}`,
      `Scan: ${chain.scanId}`,
      `Chain ID: ${chain.chainId}`,
      `Details: ${chain.details}`,
    ].join("\n")

    setText((prev) => (prev.trim() ? `${prev}\n\n${importText}` : importText))
    setInfoBanner(`Attack chain ${chain.chainId} imported into composer.`)
  }

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="rounded-md border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-zinc-500">Secure Collaboration</p>
              <h1 className="mt-1 text-2xl font-extrabold text-white">E2E Team Chat</h1>
              <p className="text-sm text-zinc-400">Replies, reactions, media, group creation, and pinned messages with tamper detection.</p>
            </div>
            <div className="inline-flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200">
              <ShieldCheck className="w-4 h-4" />
              AES-GCM + ECDSA Integrity
            </div>
          </div>
          {infoBanner && (
            <div className="mt-3 rounded-md border border-sky-500/35 bg-sky-500/10 px-3 py-2 text-xs text-sky-200">
              {infoBanner}
            </div>
          )}
        </motion.div>

        {!canRender ? (
          <div className="rounded-md border border-zinc-800 bg-zinc-900 p-6 text-sm text-zinc-300">Initializing secure chat keys...</div>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
            <motion.aside initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} className="xl:col-span-3 rounded-md border border-zinc-800 bg-zinc-900 p-3 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-white inline-flex items-center gap-2">
                  <Users className="w-4 h-4" /> Groups
                </h2>
                <button
                  onClick={() => setCreateOpen((v) => !v)}
                  className="inline-flex items-center gap-1 rounded-md bg-[#3b3486] px-2.5 py-1.5 text-xs font-semibold text-white hover:bg-[#4a439b]"
                >
                  <Plus className="w-3.5 h-3.5" /> New
                </button>
              </div>

              {createOpen && (
                <form onSubmit={handleCreateGroup} className="rounded-md border border-zinc-700 bg-zinc-950 p-3 space-y-2">
                  <input
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                    placeholder="Group name"
                    className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white outline-none focus:border-zinc-500"
                  />
                  <p className="text-[11px] text-zinc-500">Members</p>
                  <div className="grid grid-cols-2 gap-2">
                    {users.map((u) => {
                      const selected = newGroupMembers.includes(u.id)
                      return (
                        <button
                          key={u.id}
                          type="button"
                          onClick={() => {
                            if (u.id === CURRENT_USER) return
                            setNewGroupMembers((prev) =>
                              selected ? prev.filter((id) => id !== u.id) : [...prev, u.id]
                            )
                          }}
                          className={cn(
                            "rounded-md border px-2 py-1.5 text-xs",
                            selected ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-200" : "border-zinc-700 bg-zinc-900 text-zinc-300"
                          )}
                        >
                          {u.name}
                        </button>
                      )
                    })}
                  </div>
                  <button type="submit" className="w-full rounded-md bg-zinc-100 px-3 py-2 text-xs font-bold text-zinc-900 hover:bg-white">
                    Create Secure Group
                  </button>
                </form>
              )}

              <div className="space-y-1">
                {groups.map((g) => {
                  const active = g.id === selectedGroupId
                  return (
                    <button
                      key={g.id}
                      onClick={() => setSelectedGroupId(g.id)}
                      className={cn(
                        "w-full text-left rounded-md border px-3 py-2 transition-colors",
                        active ? "border-[#3b3486] bg-[#3b3486]/20" : "border-zinc-800 hover:border-zinc-600 bg-zinc-950"
                      )}
                    >
                      <p className="text-sm font-semibold text-white">{g.name}</p>
                      <p className="text-[11px] text-zinc-500">{g.members.length} members • {g.pinnedMessageIds.length} pinned</p>
                    </button>
                  )
                })}
              </div>
            </motion.aside>

            <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="xl:col-span-9 rounded-md border border-zinc-800 bg-zinc-900 flex flex-col min-h-[70vh]">
              <div className="border-b border-zinc-800 px-4 py-3">
                <h2 className="text-sm font-bold text-white inline-flex items-center gap-2">
                  <MessageCircle className="w-4 h-4" /> {selectedGroup?.name}
                </h2>
                <p className="text-xs text-zinc-500">Only group members with key material can decrypt these messages.</p>
                <p className="text-xs text-zinc-500 mt-1">
                  Classification: {selectedGroup?.metadata.classification} • Chains: {selectedGroup?.metadata.attackChains.length || 0} • Reports: {selectedGroup?.metadata.reportDetails.length || 0}
                </p>
              </div>

              {importedChains.length > 0 && (
                <div className="border-b border-zinc-800 p-3 bg-zinc-950/50">
                  <p className="text-[11px] uppercase tracking-wider text-zinc-500 mb-2 inline-flex items-center gap-1">
                    <GitBranch className="w-3.5 h-3.5" /> Imported Chain Details
                  </p>
                  <div className="space-y-2">
                    {importedChains.slice(0, 6).map((chain) => (
                      <div key={chain.id} className="rounded-md border border-zinc-700 bg-zinc-900 p-2 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                        <div className="min-w-0">
                          <p className="text-xs font-semibold text-white truncate">{chain.title}</p>
                          <p className="text-[11px] text-zinc-400 truncate">{chain.chainId} • {chain.scanId}</p>
                        </div>
                        <button
                          type="button"
                          onClick={() => importChainToComposer(chain.id)}
                          className="rounded-md border border-[#3b3486] bg-[#3b3486]/20 px-2.5 py-1 text-xs font-semibold text-white hover:bg-[#3b3486]/35"
                        >
                          Import To Chat
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {pinnedMessages.length > 0 && (
                <div className="border-b border-zinc-800 p-3 bg-zinc-950/50">
                  <p className="text-[11px] uppercase tracking-wider text-zinc-500 mb-2">Pinned</p>
                  <div className="flex flex-wrap gap-2">
                    {pinnedMessages.map((pm) => {
                      const dec = decryptedById[pm.id]
                      const preview = dec?.tampered ? "Tamper detected" : dec?.payload?.text || "Media"
                      return (
                        <button
                          key={pm.id}
                          onClick={() => setReplyToMessageId(pm.id)}
                          className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs text-amber-200"
                        >
                          {preview.slice(0, 70)}
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}

              <div className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-transparent">
                {groupMessages.map((message) => {
                  const mine = message.senderId === CURRENT_USER
                  const sender = getSender(users, message.senderId)
                  const decrypted = decryptedById[message.id]
                  const replyTo = message.replyToMessageId ? groupMessages.find((m) => m.id === message.replyToMessageId) : null
                  const replyPreview = replyTo ? decryptedById[replyTo.id]?.payload?.text ?? "Encrypted reply" : ""

                  return (
                    <motion.div
                      key={message.id}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={cn("rounded-md border p-3", mine ? "border-violet-500/40 bg-violet-500/10" : "border-zinc-800 bg-zinc-950")}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className={cn("text-[11px] px-2 py-0.5 rounded", sender?.color || "bg-zinc-700 text-zinc-200")}>{sender?.name || "Unknown"}</span>
                            <span className="text-[11px] text-zinc-500">{new Date(message.sentAt).toLocaleTimeString()}</span>
                          </div>

                          {replyTo && (
                            <div className="mt-2 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-400">
                              Reply to: {replyPreview.slice(0, 100)}
                            </div>
                          )}

                          {decrypted?.tampered ? (
                            <div className="mt-2 inline-flex items-center gap-1 rounded-md border border-red-500/40 bg-red-500/10 px-2 py-1 text-xs text-red-200">
                              <ShieldAlert className="w-3.5 h-3.5" /> Integrity check failed. Message may be tampered.
                            </div>
                          ) : (
                            <>
                              {decrypted?.payload?.text && <p className="mt-2 text-sm text-zinc-200 whitespace-pre-wrap">{decrypted.payload.text}</p>}
                              {decrypted?.payload?.media && (
                                <div className="mt-2 rounded-md border border-zinc-700 p-2 bg-zinc-900">
                                  {decrypted.payload.media.mimeType.startsWith("image/") && (
                                    <img src={decrypted.payload.media.dataUrl} alt={decrypted.payload.media.name} className="max-h-56 rounded-md" />
                                  )}
                                  {decrypted.payload.media.mimeType.startsWith("video/") && (
                                    <video controls className="max-h-56 rounded-md">
                                      <source src={decrypted.payload.media.dataUrl} type={decrypted.payload.media.mimeType} />
                                    </video>
                                  )}
                                  {!decrypted.payload.media.mimeType.startsWith("image/") && !decrypted.payload.media.mimeType.startsWith("video/") && (
                                    <a href={decrypted.payload.media.dataUrl} download={decrypted.payload.media.name} className="text-xs text-sky-300 hover:text-sky-200">
                                      Download {decrypted.payload.media.name}
                                    </a>
                                  )}
                                </div>
                              )}
                            </>
                          )}
                        </div>

                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => setReplyToMessageId(message.id)}
                            className="rounded-md border border-zinc-700 px-1.5 py-1 text-zinc-300 hover:text-white"
                            title="Reply"
                          >
                            <Reply className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => togglePin(message.id)}
                            className={cn(
                              "rounded-md border px-1.5 py-1",
                              selectedGroup?.pinnedMessageIds.includes(message.id)
                                ? "border-amber-500/50 text-amber-300"
                                : "border-zinc-700 text-zinc-300 hover:text-white"
                            )}
                            title="Pin message"
                          >
                            <Pin className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>

                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        {EMOJIS.map((emoji) => {
                          const count = message.reactions[emoji]?.length ?? 0
                          const mineReacted = message.reactions[emoji]?.includes(CURRENT_USER)
                          return (
                            <button
                              key={emoji}
                              onClick={() => toggleReaction(message.id, emoji)}
                              className={cn(
                                "rounded-full border px-2 py-0.5 text-xs",
                                mineReacted ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-200" : "border-zinc-700 text-zinc-300"
                              )}
                            >
                              {emoji} {count > 0 ? count : ""}
                            </button>
                          )
                        })}
                        <span className="text-[11px] text-zinc-500 inline-flex items-center gap-1 ml-1">
                          <ShieldCheck className="w-3 h-3" /> Signed
                        </span>
                      </div>
                    </motion.div>
                  )
                })}

                {groupMessages.length === 0 && (
                  <div className="text-sm text-zinc-500">No messages yet. Send the first encrypted message.</div>
                )}
              </div>

              <form onSubmit={handleSend} className="border-t border-zinc-800 p-3 space-y-2">
                {replyMessage && (
                  <div className="flex items-center justify-between rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-300">
                    <span>Replying to: {(decryptedById[replyMessage.id]?.payload?.text || "Media message").slice(0, 120)}</span>
                    <button
                      type="button"
                      onClick={() => setReplyToMessageId(null)}
                      className="text-zinc-400 hover:text-zinc-200"
                      aria-label="Cancel reply"
                      title="Cancel reply"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                )}

                {attachment && (
                  <div className="flex items-center justify-between rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-300">
                    <span className="inline-flex items-center gap-2">
                      {attachment.mimeType.startsWith("image/") ? <ImageIcon className="w-3.5 h-3.5" /> : attachment.mimeType.startsWith("video/") ? <Video className="w-3.5 h-3.5" /> : <FileText className="w-3.5 h-3.5" />}
                      {attachment.name}
                    </span>
                    <button
                      type="button"
                      onClick={() => setAttachment(undefined)}
                      className="text-zinc-400 hover:text-zinc-200"
                      aria-label="Remove attachment"
                      title="Remove attachment"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                )}

                <div className="flex gap-2">
                  <input
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                    placeholder="Write an encrypted message..."
                    className="flex-1 rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-white outline-none focus:border-zinc-500"
                  />

                  <label className="inline-flex items-center justify-center rounded-md border border-zinc-700 px-3 py-2 text-zinc-300 hover:text-white cursor-pointer">
                    <input
                      type="file"
                      className="hidden"
                      onChange={onPickMedia}
                      accept="image/*,video/*,.pdf,.txt,.doc,.docx,.csv,.json"
                      aria-label="Attach media"
                      title="Attach media"
                    />
                    <SmilePlus className="w-4 h-4 mr-1" />
                    <ImageIcon className="w-4 h-4" />
                  </label>

                  <button
                    type="submit"
                    className="inline-flex items-center gap-1 rounded-md bg-[#3b3486] px-4 py-2 text-sm font-semibold text-white hover:bg-[#4a439b]"
                  >
                    <Send className="w-4 h-4" /> Send
                  </button>
                </div>
              </form>
            </motion.section>
          </div>
        )}
      </div>
    </DashboardLayout>
  )
}
