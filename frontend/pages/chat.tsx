import React, { ChangeEvent, FormEvent, useEffect, useMemo, useRef, useState } from "react"
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
  Download,
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
  isAdminUser,
  loadSecureChatState,
  saveSecureChatState,
  verifyAndDecryptMessage,
  getSecureChatSerializedState,
  loadSecureChatStateFromSerialized,
  storeSecureChatSerializedState,
} from "@/lib/secureChatStore"
import { createChatSyncClient } from "@/lib/chatSync"
import { getAuthSession } from "@/lib/authSession"
import { useRouter } from "next/router"

const EMOJIS = ["👍", "🔥", "✅", "🚨", "👀"]

function getSender(users: ChatUser[], id: string) {
  return users.find((u) => u.id === id)
}

export default function ChatPage() {
  const router = useRouter()
  const currentUserId = getCurrentUserId()
  const isAdmin = isAdminUser(currentUserId)
  const [users, setUsers] = useState<ChatUser[]>([])
  const [groups, setGroups] = useState<ChatGroup[]>([])
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [selectedGroupId, setSelectedGroupId] = useState<string>("")
  const [text, setText] = useState("")
  const [replyToMessageId, setReplyToMessageId] = useState<string | null>(null)
  const [attachment, setAttachment] = useState<MediaAttachment | undefined>(undefined)
  const [viewerAttachment, setViewerAttachment] = useState<MediaAttachment | null>(null)
  const [newGroupName, setNewGroupName] = useState("")
  const [newGroupMembers, setNewGroupMembers] = useState<string[]>([currentUserId])
  const [createOpen, setCreateOpen] = useState(false)
  const [infoBanner, setInfoBanner] = useState<string>("Checking auth...")
  const [relayConnected, setRelayConnected] = useState(false)
  const [isStateLoaded, setIsStateLoaded] = useState(false)
  const latestSnapshotRef = useRef({ users: [] as ChatUser[], groups: [] as ChatGroup[], messages: [] as ChatMessage[], selectedGroupId: "" })
  const syncRef = useRef<ReturnType<typeof createChatSyncClient> | null>(null)
  const skipNextSaveRef = useRef(false)
  const skipNextPublishRef = useRef(false)

  const refreshGroupMessages = async (groupId: string) => {
    if (!groupId) return
    try {
      const res = await fetch(`/api/chat/messages?groupId=${encodeURIComponent(groupId)}`)
      if (!res.ok) return
      const data = await res.json()
      if (!Array.isArray(data.messages)) return

      setMessages((prev) => {
        const merged = new Map<string, typeof prev[number]>()
        for (const message of prev) merged.set(message.id, message)
        for (const message of data.messages) merged.set(message.id, message)
        return Array.from(merged.values()).sort((a, b) => a.sentAt - b.sentAt)
      })
    } catch {
      // ignore transient refresh failures
    }
  }

  const visibleGroups = useMemo(
    () => groups.filter((g) => g.members.includes(currentUserId)),
    [groups, currentUserId]
  )

  const selectedGroup = useMemo(
    () => visibleGroups.find((g) => g.id === selectedGroupId) ?? visibleGroups[0] ?? null,
    [visibleGroups, selectedGroupId]
  )

  const groupMessages = useMemo(() => {
    return messages
        .filter((m) => m.groupId === (selectedGroup?.id || ""))
      .sort((a, b) => a.sentAt - b.sentAt)
      }, [messages, selectedGroup])

  const [decryptedById, setDecryptedById] = useState<Record<string, DecryptedMessage>>({})

  // Auth check
  useEffect(() => {
    const session = getAuthSession()
    if (!session) {
      router.push("/auth")
      return
    }
    setInfoBanner(`Logged in as ${session.name} (${session.role}) | User ID: ${currentUserId}`)
  }, [router, currentUserId])

  useEffect(() => {
    let mounted = true

    const hydrateChat = async () => {
      try {
        const res = await fetch("/api/chat/state")
        if (!res.ok) {
          throw new Error("Backend unconfigured or unavailable")
        }
        const data = await res.json()
        if (Array.isArray(data.users) && Array.isArray(data.groups) && Array.isArray(data.messages) && data.groups.length) {
          if (!mounted) return
          setUsers(data.users)
          setGroups(data.groups)
          setMessages(data.messages)
          setSelectedGroupId(data.selectedGroupId || data.groups[0]?.id || "")
          setIsStateLoaded(true)
          setInfoBanner("Loaded chat state from Supabase backend.")
          return
        }
      } catch (err) {
        console.warn("Retrying local state load due to backend status:", err)
      }


      try {
        const state = await loadSecureChatState()
        if (!mounted) return
        setUsers(state.users)
        setGroups(state.groups)
        setMessages(state.messages)
        setSelectedGroupId(state.selectedGroupId)
        setIsStateLoaded(true)
        setInfoBanner("Loaded local chat state.")
      } catch {
        if (!mounted) return
        setInfoBanner("Secure chat initialization failed. Please refresh.")
      }
    }

    void hydrateChat()

    return () => {
      mounted = false
    }
  }, [])

  useEffect(() => {
    if (!isStateLoaded || !selectedGroupId) return

    const controller = new AbortController()
    void refreshGroupMessages(selectedGroupId)

    return () => {
      controller.abort()
    }
  }, [isStateLoaded, selectedGroupId])

  useEffect(() => {
    if (!isStateLoaded) return

    const sync = createChatSyncClient({
      getSnapshot: () => {
        const state = JSON.stringify(latestSnapshotRef.current)
        storeSecureChatSerializedState(state)
        return state
      },
      onMessage: (message) => {
        skipNextPublishRef.current = true
        setMessages((prev) => {
          if (prev.some((m) => m.id === message.id)) return prev
          return [...prev, message]
        })
        void refreshGroupMessages(message.groupId)
        setInfoBanner(`✓ Message received from peer | User: ${currentUserId}`)
      },
      onSnapshot: (serializedState) => {
        skipNextSaveRef.current = true
        skipNextPublishRef.current = true
        storeSecureChatSerializedState(serializedState)
        loadSecureChatStateFromSerialized(serializedState)
          .then((state) => {
            setUsers(state.users)
            setGroups(state.groups)
            setMessages(state.messages)
            setSelectedGroupId(state.selectedGroupId)
            setInfoBanner(`✓ Update from peer | User: ${currentUserId} | Messages: ${state.messages.length}`)
          })
          .catch(() => {
            setInfoBanner("Received invalid sync payload.")
          })
      },
      onStatus: (status) => {
        if (status.includes("Connected")) {
          setRelayConnected(true)
          setInfoBanner(`✓ Relay connected | User: ${currentUserId}`)
        } else {
          setRelayConnected(status.includes("connected"))
          setInfoBanner(status)
        }
      },
    })

    syncRef.current = sync
    sync.connect()
    setRelayConnected(true)
    return () => {
      sync.disconnect()
      syncRef.current = null
      setRelayConnected(false)
    }
  }, [isStateLoaded, currentUserId])

  useEffect(() => {
    latestSnapshotRef.current = { users, groups, messages, selectedGroupId }
  }, [users, groups, messages, selectedGroupId])

  // NOTE: Periodic polling removed — BroadcastChannel handles cross-tab sync in real time.

  useEffect(() => {
    if (!users.length || !groups.length) return

    if (skipNextSaveRef.current) {
      skipNextSaveRef.current = false
      return
    }

    saveSecureChatState({
      users,
      groups,
      messages,
      selectedGroupId,
    })
  }, [users, groups, messages, selectedGroupId])

  useEffect(() => {
    if (!users.length || !groups.length) return

    if (skipNextPublishRef.current) {
      skipNextPublishRef.current = false
      return
    }

    const state = {
      users,
      groups,
      messages,
      selectedGroupId,
    }

    const serialized = JSON.stringify(state)
    syncRef.current?.publishSnapshot(serialized)
  }, [users, groups, messages, selectedGroupId, currentUserId])


  // NOTE: Backend POST removed — state is persisted to LocalStorage via saveSecureChatState.

  useEffect(() => {
    if (!selectedGroupId && visibleGroups[0]) {
      setSelectedGroupId(visibleGroups[0].id)
    }
  }, [visibleGroups, selectedGroupId])

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

    if (!isAdmin) {
      setInfoBanner("Only admin can create groups.")
      return
    }

    try {
      const group = await createGroup({
        name: cleanName,
        members: Array.from(new Set(newGroupMembers)),
        ownerUserId: currentUserId,
      })

      setGroups((prev) => [group, ...prev])
      setSelectedGroupId(group.id)
      setNewGroupName("")
      setNewGroupMembers([currentUserId])
      setCreateOpen(false)
      setInfoBanner(`Group ${cleanName} created with E2E key material.`)
    } catch (error) {
      const message = error instanceof Error ? error.message : "Group creation failed"
      setInfoBanner(message)
    }
  }

  const onPickMedia = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ""
    if (!file) return

    if (file.size > 20 * 1024 * 1024) {
      setInfoBanner("Media size limit is 20MB for LAN chat.")
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

    const me = users.find((u) => u.id === currentUserId)
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

    console.log(`[${currentUserId}] Sending message to group ${selectedGroup.id}:`, payload.text)
    const saveResponse = await fetch("/api/chat/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    }).catch((error) => {
      console.error("Chat backend save failed:", error)
      return null
    })

    if (!saveResponse || !saveResponse.ok) {
      setInfoBanner("Message could not be saved to Supabase.")
      return
    }

    setMessages((prev) => [...prev, message])
    syncRef.current?.publishMessage(message)
    void refreshGroupMessages(selectedGroup.id)
    setText("")
    setReplyToMessageId(null)
    setAttachment(undefined)
    setInfoBanner(`✓ Message sent from ${me.name}`)
  }

  const toggleReaction = (messageId: string, emoji: string) => {
    setMessages((prev) =>
      prev.map((m) => {
        if (m.id !== messageId) return m
        const existing = m.reactions[emoji] ?? []
        const hasMine = existing.includes(currentUserId)
        return {
          ...m,
          reactions: {
            ...m.reactions,
            [emoji]: hasMine ? existing.filter((uid) => uid !== currentUserId) : [...existing, currentUserId],
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

  const decodeTextDataUrl = (dataUrl: string) => {
    try {
      const raw = dataUrl.split(",")[1] || ""
      const atobFn = typeof window !== "undefined" ? window.atob : globalThis.atob
      if (!atobFn) return "Unable to decode text content."
      const bytes = Uint8Array.from(atobFn(raw), (char) => char.charCodeAt(0))
      return new TextDecoder().decode(bytes)
    } catch {
      return "Unable to decode text content."
    }
  }

  const viewerKind = useMemo(() => {
    if (!viewerAttachment) return "file"
    if (viewerAttachment.mimeType.startsWith("image/")) return "image"
    if (viewerAttachment.mimeType.startsWith("video/")) return "video"
    if (viewerAttachment.mimeType === "application/pdf" || viewerAttachment.name.toLowerCase().endsWith(".pdf")) return "pdf"
    if (
      viewerAttachment.mimeType.startsWith("text/") ||
      /\.(txt|log|csv|json|md|xml|yaml|yml|ini|conf|env)$/i.test(viewerAttachment.name)
    ) {
      return "text"
    }
    return "file"
  }, [viewerAttachment])

  const viewerText = useMemo(() => {
    if (!viewerAttachment || viewerKind !== "text") return ""
    return decodeTextDataUrl(viewerAttachment.dataUrl)
  }, [viewerAttachment, viewerKind])

  const canRender = users.length > 0 && groups.length > 0

  const importedChains = useMemo(() => {
    if (!selectedGroup) return []
    return [...selectedGroup.metadata.attackChains].sort((a, b) => b.addedAt - a.addedAt)
  }, [selectedGroup])

  const importedReports = useMemo(() => {
    if (!selectedGroup) return []
    return [...selectedGroup.metadata.reportDetails].sort((a, b) => b.addedAt - a.addedAt)
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

  const importReportToComposer = (reportId: string) => {
    if (!selectedGroup) return
    const report = selectedGroup.metadata.reportDetails.find((item) => item.id === reportId)
    if (!report) return

    const importText = [
      `Imported Report Detail: ${report.title}`,
      `Scan: ${report.scanId}`,
      `Finding: ${report.findingId || "N/A"}`,
      `Details: ${report.details}`,
    ].join("\n")

    setText((prev) => (prev.trim() ? `${prev}\n\n${importText}` : importText))
    setInfoBanner(`Report detail imported into composer.`)
  }

  const openAttachmentViewer = (media: MediaAttachment) => {
    setViewerAttachment(media)
  }

  const closeAttachmentViewer = () => {
    setViewerAttachment(null)
  }

  const downloadAttachment = () => {
    if (!viewerAttachment) return
    const link = document.createElement("a")
    link.href = viewerAttachment.dataUrl
    link.download = viewerAttachment.name
    link.rel = "noopener noreferrer"
    document.body.appendChild(link)
    link.click()
    link.remove()
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
                {isAdmin && (
                  <button
                    onClick={() => setCreateOpen((v) => !v)}
                    className="inline-flex items-center gap-1 rounded-md bg-[#3b3486] px-2.5 py-1.5 text-xs font-semibold text-white hover:bg-[#4a439b]"
                  >
                    <Plus className="w-3.5 h-3.5" /> New
                  </button>
                )}
              </div>

              {createOpen && isAdmin && (
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
                            if (u.id === currentUserId) return
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
                {visibleGroups.map((g) => {
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

              {importedReports.length > 0 && (
                <div className="border-b border-zinc-800 p-3 bg-zinc-950/40">
                  <p className="text-[11px] uppercase tracking-wider text-zinc-500 mb-2 inline-flex items-center gap-1">
                    <FileText className="w-3.5 h-3.5" /> Imported Report Details
                  </p>
                  <div className="space-y-2">
                    {importedReports.slice(0, 6).map((report) => (
                      <div key={report.id} className="rounded-md border border-zinc-700 bg-zinc-900 p-2 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                        <div className="min-w-0">
                          <p className="text-xs font-semibold text-white truncate">{report.title}</p>
                          <p className="text-[11px] text-zinc-400 truncate">{report.scanId} • {report.findingId || "General"}</p>
                        </div>
                        <button
                          type="button"
                          onClick={() => importReportToComposer(report.id)}
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
                  const mine = message.senderId === currentUserId
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
                                (() => {
                                  const media = decrypted.payload?.media
                                  if (!media) return null
                                  return (
                                <button
                                  type="button"
                                  onClick={() => openAttachmentViewer(media)}
                                  className="mt-2 block w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-left transition-colors hover:border-sky-500/50 hover:bg-zinc-800/80"
                                >
                                  <div className="flex items-center gap-2 text-xs text-zinc-300">
                                    {media.mimeType.startsWith("image/") ? (
                                      <ImageIcon className="w-3.5 h-3.5" />
                                    ) : media.mimeType.startsWith("video/") ? (
                                      <Video className="w-3.5 h-3.5" />
                                    ) : (
                                      <FileText className="w-3.5 h-3.5" />
                                    )}
                                    <span className="truncate">{media.name}</span>
                                    <span className="text-zinc-500">Open preview</span>
                                  </div>
                                  <p className="mt-1 text-[11px] text-zinc-500">Click to view in a popup and download.</p>
                                </button>
                                  )
                                })()
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
                          const mineReacted = message.reactions[emoji]?.includes(currentUserId)
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
                      accept="*/*"
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

      {viewerAttachment && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4 py-6">
          <div className="w-full max-w-5xl rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl">
            <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-white">{viewerAttachment.name}</p>
                <p className="text-[11px] text-zinc-500">{viewerAttachment.mimeType}</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={downloadAttachment}
                  className="inline-flex items-center gap-1 rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-500/20"
                >
                  <Download className="h-3.5 w-3.5" /> Download
                </button>
                <button
                  type="button"
                  onClick={closeAttachmentViewer}
                  className="rounded-md border border-zinc-700 px-2.5 py-2 text-zinc-300 hover:text-white"
                  aria-label="Close attachment viewer"
                  title="Close"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            <div className="max-h-[75vh] overflow-auto p-4">
              {viewerKind === "image" && (
                <img src={viewerAttachment.dataUrl} alt={viewerAttachment.name} className="mx-auto max-h-[70vh] w-auto rounded-lg object-contain" />
              )}

              {viewerKind === "video" && (
                <video controls autoPlay className="mx-auto max-h-[70vh] w-full rounded-lg bg-black">
                  <source src={viewerAttachment.dataUrl} type={viewerAttachment.mimeType} />
                </video>
              )}

              {viewerKind === "pdf" && (
                <iframe
                  title={viewerAttachment.name}
                  src={viewerAttachment.dataUrl}
                  className="h-[70vh] w-full rounded-lg border border-zinc-800 bg-white"
                />
              )}

              {viewerKind === "text" && (
                <pre className="whitespace-pre-wrap break-words rounded-lg border border-zinc-800 bg-zinc-900 p-4 text-sm leading-6 text-zinc-200">
                  {viewerText}
                </pre>
              )}

              {viewerKind === "file" && (
                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 text-sm text-zinc-300">
                  This file type cannot be previewed here. Use download to open it locally.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </DashboardLayout>
  )
}
