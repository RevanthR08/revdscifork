import React, { FormEvent, useEffect, useMemo, useState } from "react"
import DashboardLayout from "@/components/layout/DashboardLayout"
import { motion } from "framer-motion"
import { ShieldCheck, Users, Plus, FileText, GitBranch, Save } from "lucide-react"
import {
  type ChatGroup,
  type ChatMessage,
  type ChatUser,
  createGroup,
  getCurrentUserId,
  loadSecureChatState,
  saveSecureChatState,
  verifyAndDecryptMessage,
} from "@/lib/secureChatStore"
import { cn } from "@/lib/utils"
import { getMockAnalysisList, getMockChains, getMockFindings, getMockSummary } from "@/lib/mockData"

const CURRENT_USER = getCurrentUserId()

export default function ChatAdminPage() {
  const [users, setUsers] = useState<ChatUser[]>([])
  const [groups, setGroups] = useState<ChatGroup[]>([])
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [selectedGroupId, setSelectedGroupId] = useState("")
  const [newGroupName, setNewGroupName] = useState("")
  const [newGroupMembers, setNewGroupMembers] = useState<string[]>([CURRENT_USER])
  const [memberToAdd, setMemberToAdd] = useState("")
  const [classification, setClassification] = useState<"internal" | "confidential" | "restricted">("confidential")
  const [tagsInput, setTagsInput] = useState("")
  const [status, setStatus] = useState("")
  const [decPreview, setDecPreview] = useState<Record<string, string>>({})

  const [scanId, setScanId] = useState("")
  const [chainId, setChainId] = useState("")
  const [chainDetails, setChainDetails] = useState("")
  const [reportFindingId, setReportFindingId] = useState("")
  const [reportDetails, setReportDetails] = useState("")

  const analyses = useMemo(() => getMockAnalysisList(), [])
  const chains = useMemo(() => (scanId ? getMockChains(scanId) : []), [scanId])
  const findings = useMemo(() => (scanId ? getMockFindings(scanId) : []), [scanId])
  const summary = useMemo(() => (scanId ? getMockSummary(scanId) : null), [scanId])

  const selectedGroup = useMemo(() => groups.find((g) => g.id === selectedGroupId) ?? null, [groups, selectedGroupId])
  const groupMessages = useMemo(
    () => messages.filter((m) => m.groupId === selectedGroupId).sort((a, b) => b.sentAt - a.sentAt),
    [messages, selectedGroupId]
  )

  useEffect(() => {
    let mounted = true
    loadSecureChatState()
      .then((state) => {
        if (!mounted) return
        setUsers(state.users)
        setGroups(state.groups)
        setMessages(state.messages)
        setSelectedGroupId(state.selectedGroupId)
      })
      .catch(() => setStatus("Failed to load chat admin state."))

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

    const run = async () => {
      const next: Record<string, string> = {}
      for (const msg of groupMessages.slice(0, 20)) {
        const dec = await verifyAndDecryptMessage({ message: msg, users, groups })
        next[msg.id] = dec.tampered ? "Tamper detected" : dec.payload?.text || dec.payload?.media?.name || "Encrypted"
      }
      if (active) setDecPreview(next)
    }

    if (groupMessages.length) {
      run().catch(() => {
        if (active) setStatus("Could not decrypt previews in admin view.")
      })
    } else {
      setDecPreview({})
    }

    return () => {
      active = false
    }
  }, [groupMessages, users, groups])

  useEffect(() => {
    if (!selectedGroup) return
    setClassification(selectedGroup.metadata.classification)
    setTagsInput(selectedGroup.metadata.tags.join(", "))
    if (!scanId && analyses[0]?.scan_id) {
      setScanId(analyses[0].scan_id)
    }
  }, [selectedGroup, analyses, scanId])

  const handleCreateGroup = async (e: FormEvent) => {
    e.preventDefault()
    const name = newGroupName.trim()
    if (!name || newGroupMembers.length < 2) {
      setStatus("Group needs name and at least 2 members.")
      return
    }

    const group = await createGroup({
      name,
      members: newGroupMembers,
      ownerUserId: CURRENT_USER,
    })

    setGroups((prev) => [group, ...prev])
    setSelectedGroupId(group.id)
    setNewGroupName("")
    setNewGroupMembers([CURRENT_USER])
    setStatus(`Group ${name} created.`)
  }

  const addMember = () => {
    if (!selectedGroup || !memberToAdd) return
    if (selectedGroup.members.includes(memberToAdd)) return

    setGroups((prev) =>
      prev.map((g) =>
        g.id === selectedGroup.id
          ? {
              ...g,
              members: [...g.members, memberToAdd],
            }
          : g
      )
    )
    setMemberToAdd("")
    setStatus("Member added to conversation.")
  }

  const saveMetadata = () => {
    if (!selectedGroup) return
    const tags = tagsInput
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean)

    setGroups((prev) =>
      prev.map((g) =>
        g.id === selectedGroup.id
          ? {
              ...g,
              metadata: {
                ...g.metadata,
                classification,
                tags,
              },
            }
          : g
      )
    )
    setStatus("Metadata saved locally.")
  }

  const addAttackChainMetadata = () => {
    if (!selectedGroup || !scanId || !chainId) return
    const chain = chains.find((c) => c.chain_id === chainId)
    if (!chain) return

    setGroups((prev) =>
      prev.map((g) =>
        g.id === selectedGroup.id
          ? {
              ...g,
              metadata: {
                ...g.metadata,
                attackChains: [
                  {
                    id: `${Date.now()}-${chain.chain_id}`,
                    scanId,
                    chainId: chain.chain_id,
                    title: chain.title,
                    details: chainDetails.trim() || `Confidence ${chain.chain_confidence}`,
                    addedAt: Date.now(),
                  },
                  ...g.metadata.attackChains,
                ],
              },
            }
          : g
      )
    )

    setChainDetails("")
    setStatus("Attack chain metadata attached to conversation.")
  }

  const addReportMetadata = () => {
    if (!selectedGroup || !scanId) return

    const finding = findings.find((f) => f.id === reportFindingId)
    const title = finding?.title || summary?.sections.executive_summary.slice(0, 80) || "Report Note"
    const details = reportDetails.trim() || summary?.sections.attack_narrative || ""

    if (!details) {
      setStatus("Provide report details before adding.")
      return
    }

    setGroups((prev) =>
      prev.map((g) =>
        g.id === selectedGroup.id
          ? {
              ...g,
              metadata: {
                ...g.metadata,
                reportDetails: [
                  {
                    id: `${Date.now()}-${scanId}`,
                    scanId,
                    findingId: finding?.id,
                    title,
                    details,
                    addedAt: Date.now(),
                  },
                  ...g.metadata.reportDetails,
                ],
              },
            }
          : g
      )
    )

    setReportDetails("")
    setStatus("Report detail added to metadata.")
  }

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="rounded-md border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-zinc-500">Conversation Governance</p>
              <h1 className="text-2xl font-extrabold text-white">Chat Admin</h1>
            </div>
            <div className="inline-flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200">
              <ShieldCheck className="w-4 h-4" /> Persisted locally with metadata controls
            </div>
          </div>
          {status && <div className="mt-3 rounded-md border border-sky-500/35 bg-sky-500/10 px-3 py-2 text-xs text-sky-200">{status}</div>}
        </motion.div>

        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
          <motion.aside initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} className="xl:col-span-3 rounded-md border border-zinc-800 bg-zinc-900 p-3 space-y-3">
            <h2 className="text-sm font-bold text-white inline-flex items-center gap-2"><Users className="w-4 h-4" /> Conversations</h2>

            <form onSubmit={handleCreateGroup} className="rounded-md border border-zinc-700 bg-zinc-950 p-3 space-y-2">
              <input
                value={newGroupName}
                onChange={(e) => setNewGroupName(e.target.value)}
                placeholder="New conversation name"
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white outline-none focus:border-zinc-500"
              />
              <div className="grid grid-cols-2 gap-1.5">
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
                        "rounded-md border px-2 py-1 text-xs",
                        selected ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-200" : "border-zinc-700 bg-zinc-900 text-zinc-300"
                      )}
                    >
                      {u.name}
                    </button>
                  )
                })}
              </div>
              <button type="submit" className="w-full rounded-md bg-[#3b3486] px-3 py-2 text-xs font-semibold text-white hover:bg-[#4a439b] inline-flex items-center justify-center gap-1">
                <Plus className="w-3.5 h-3.5" /> Create
              </button>
            </form>

            <div className="space-y-1">
              {groups.map((group) => (
                <button
                  key={group.id}
                  onClick={() => setSelectedGroupId(group.id)}
                  className={cn(
                    "w-full rounded-md border px-3 py-2 text-left",
                    selectedGroupId === group.id ? "border-[#3b3486] bg-[#3b3486]/20" : "border-zinc-800 bg-zinc-950"
                  )}
                >
                  <p className="text-sm font-semibold text-white">{group.name}</p>
                  <p className="text-[11px] text-zinc-500">{group.members.length} members • {messages.filter((m) => m.groupId === group.id).length} messages</p>
                </button>
              ))}
            </div>
          </motion.aside>

          <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="xl:col-span-9 rounded-md border border-zinc-800 bg-zinc-900 p-4 space-y-4">
            {!selectedGroup ? (
              <div className="text-sm text-zinc-500">Select a conversation.</div>
            ) : (
              <>
                <div className="rounded-md border border-zinc-800 bg-zinc-950 p-3 space-y-3">
                  <h3 className="text-sm font-bold text-white">Metadata and Members</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <select
                      value={classification}
                      onChange={(e) => setClassification(e.target.value as "internal" | "confidential" | "restricted")}
                      aria-label="Conversation classification"
                      title="Conversation classification"
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white"
                    >
                      <option value="internal">internal</option>
                      <option value="confidential">confidential</option>
                      <option value="restricted">restricted</option>
                    </select>
                    <input
                      value={tagsInput}
                      onChange={(e) => setTagsInput(e.target.value)}
                      placeholder="tags, comma separated"
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white"
                    />
                    <button onClick={saveMetadata} className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-bold text-zinc-900 hover:bg-white inline-flex items-center justify-center gap-1">
                      <Save className="w-4 h-4" /> Save metadata
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    {selectedGroup.members.map((mid) => {
                      const member = users.find((u) => u.id === mid)
                      return (
                        <span key={mid} className="px-2 py-0.5 rounded-md text-xs border border-zinc-700 text-zinc-200 bg-zinc-900">
                          {member?.name || mid}
                        </span>
                      )
                    })}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <select
                      value={memberToAdd}
                      onChange={(e) => setMemberToAdd(e.target.value)}
                      aria-label="Member to add"
                      title="Member to add"
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white"
                    >
                      <option value="">Select member</option>
                      {users
                        .filter((u) => !selectedGroup.members.includes(u.id))
                        .map((u) => (
                          <option key={u.id} value={u.id}>
                            {u.name}
                          </option>
                        ))}
                    </select>
                    <button onClick={addMember} className="rounded-md bg-[#3b3486] px-3 py-2 text-sm font-semibold text-white hover:bg-[#4a439b] inline-flex items-center justify-center gap-1">
                      <Plus className="w-4 h-4" /> Add member
                    </button>
                  </div>
                </div>

                <div className="rounded-md border border-zinc-800 bg-zinc-950 p-3 space-y-2">
                  <h3 className="text-sm font-bold text-white inline-flex items-center gap-2"><GitBranch className="w-4 h-4" /> Attach Attack Chain Metadata</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <select
                      value={scanId}
                      onChange={(e) => setScanId(e.target.value)}
                      aria-label="Scan selection for attack chain"
                      title="Scan selection for attack chain"
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white"
                    >
                      <option value="">Select scan</option>
                      {analyses.map((a) => (
                        <option key={a.scan_id} value={a.scan_id}>{a.file_name}</option>
                      ))}
                    </select>
                    <select
                      value={chainId}
                      onChange={(e) => setChainId(e.target.value)}
                      aria-label="Attack chain selection"
                      title="Attack chain selection"
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white"
                    >
                      <option value="">Select chain</option>
                      {chains.map((c) => (
                        <option key={c.chain_id} value={c.chain_id}>{c.title}</option>
                      ))}
                    </select>
                    <button onClick={addAttackChainMetadata} className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-bold text-zinc-900 hover:bg-white">Attach chain</button>
                  </div>
                  <textarea
                    value={chainDetails}
                    onChange={(e) => setChainDetails(e.target.value)}
                    placeholder="Optional chain details"
                    className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white min-h-[72px]"
                  />
                </div>

                <div className="rounded-md border border-zinc-800 bg-zinc-950 p-3 space-y-2">
                  <h3 className="text-sm font-bold text-white inline-flex items-center gap-2"><FileText className="w-4 h-4" /> Attach Report Details</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <select
                      value={scanId}
                      onChange={(e) => setScanId(e.target.value)}
                      aria-label="Scan selection for report detail"
                      title="Scan selection for report detail"
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white"
                    >
                      <option value="">Select scan</option>
                      {analyses.map((a) => (
                        <option key={a.scan_id} value={a.scan_id}>{a.file_name}</option>
                      ))}
                    </select>
                    <select
                      value={reportFindingId}
                      onChange={(e) => setReportFindingId(e.target.value)}
                      aria-label="Finding selection"
                      title="Finding selection"
                      className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white"
                    >
                      <option value="">Select finding (optional)</option>
                      {findings.slice(0, 50).map((f) => (
                        <option key={f.id} value={f.id}>{f.title}</option>
                      ))}
                    </select>
                    <button onClick={addReportMetadata} className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-bold text-zinc-900 hover:bg-white">Attach report detail</button>
                  </div>
                  <textarea
                    value={reportDetails}
                    onChange={(e) => setReportDetails(e.target.value)}
                    placeholder={summary?.sections.executive_summary || "Report detail note"}
                    className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-white min-h-[92px]"
                  />
                </div>

                <div className="rounded-md border border-zinc-800 bg-zinc-950 p-3">
                  <h3 className="text-sm font-bold text-white mb-2">Conversation Preview</h3>
                  <div className="space-y-2 max-h-[280px] overflow-y-auto scrollbar-transparent">
                    {groupMessages.map((m) => (
                      <div key={m.id} className="rounded-md border border-zinc-800 bg-zinc-900 p-2">
                        <p className="text-[11px] text-zinc-500">{new Date(m.sentAt).toLocaleString()}</p>
                        <p className="text-sm text-zinc-200">{decPreview[m.id] || "Decrypting..."}</p>
                      </div>
                    ))}
                    {groupMessages.length === 0 && <p className="text-sm text-zinc-500">No messages in this conversation.</p>}
                  </div>
                </div>
              </>
            )}
          </motion.section>
        </div>
      </div>
    </DashboardLayout>
  )
}
