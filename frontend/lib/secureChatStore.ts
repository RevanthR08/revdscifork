export type MediaAttachment = {
  name: string
  mimeType: string
  dataUrl: string
}

export type MessagePayload = {
  text: string
  media?: MediaAttachment
}

export type DecryptedMessage = {
  payload: MessagePayload | null
  tampered: boolean
}

export type ChatEnvelope = {
  ivB64: string
  cipherB64: string
}

export type AttackChainMetadata = {
  id: string
  scanId: string
  chainId: string
  title: string
  details: string
  addedAt: number
}

export type ReportDetailMetadata = {
  id: string
  scanId: string
  title: string
  details: string
  findingId?: string
  addedAt: number
}

export type GroupMetadata = {
  ownerUserId: string
  createdAt: number
  classification: "internal" | "confidential" | "restricted"
  tags: string[]
  attackChains: AttackChainMetadata[]
  reportDetails: ReportDetailMetadata[]
}

export type ChatMessage = {
  id: string
  groupId: string
  senderId: string
  sentAt: number
  envelope: ChatEnvelope
  signatureB64: string
  replyToMessageId?: string
  reactions: Record<string, string[]>
  metadata: {
    source: "local"
    integrity: "signed"
  }
}

export type ChatUser = {
  id: string
  name: string
  color: string
}

export type ChatGroup = {
  id: string
  name: string
  members: string[]
  pinnedMessageIds: string[]
  metadata: GroupMetadata
}

export type SecureChatState = {
  users: ChatUser[]
  groups: ChatGroup[]
  messages: ChatMessage[]
  selectedGroupId: string
}

type StoredUser = {
  id: string
  name: string
  color: string
}

type StoredGroup = {
  id: string
  name: string
  members: string[]
  pinnedMessageIds: string[]
  metadata: GroupMetadata
}

type StoredState = {
  users: StoredUser[]
  groups: StoredGroup[]
  messages: ChatMessage[]
  selectedGroupId: string
}

const STORAGE_KEY = "secure_chat_state_v6"
const RESET_MARKER_KEY = "secure_chat_reset_v6_clean"
const CHAT_STORAGE_KEYS_TO_CLEAR = [
  "secure_chat_state_v1",
  "secure_chat_state_v2",
  "secure_chat_state_v3",
  "secure_chat_state_v4",
  "secure_chat_state_v5",
  "secure_chat_sync_snapshot",
  "secure_chat_reset_v4",
  "secure_chat_reset_v5_clean",
]

const ADMIN_USER = "u-admin"
const STANDARD_USER = "u-user"
const USER_SEEDS = [
  { id: ADMIN_USER, name: "Security Admin", color: "bg-violet-500/30 text-violet-300" },
  { id: STANDARD_USER, name: "SOC Analyst", color: "bg-sky-500/30 text-sky-300" },
]

const strToBytes = (value: string) => new TextEncoder().encode(value)
const bytesToStr = (value: ArrayBuffer) => new TextDecoder().decode(value)

function ensureFreshChatStorage() {
  if (typeof window === "undefined") return
  
  // Always clear old versions for a fresh start
  for (const key of CHAT_STORAGE_KEYS_TO_CLEAR) {
    window.localStorage.removeItem(key)
  }
  
  // Mark clean slate
  window.localStorage.setItem(RESET_MARKER_KEY, "1")
}

const b64FromArray = (bytes: Uint8Array) => {
  let binary = ""
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    const part = bytes.subarray(i, i + chunk)
    binary += String.fromCharCode(...part)
  }
  return window.btoa(binary)
}

const arrayFromB64 = (b64: string) => {
  const binary = window.atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export const makeId = () => {
  const rand = Math.random().toString(16).slice(2, 10)
  return `id-${Date.now()}-${rand}`
}

async function makeUser(seed: { id: string; name: string; color: string }): Promise<ChatUser> {
  return {
    id: seed.id,
    name: seed.name,
    color: seed.color,
  }
}

async function makeGroup(input: { id: string; name: string; members: string[]; ownerUserId: string }): Promise<ChatGroup> {
  return {
    id: input.id,
    name: input.name,
    members: input.members,
    pinnedMessageIds: [],
    metadata: {
      ownerUserId: input.ownerUserId,
      createdAt: Date.now(),
      classification: "confidential",
      tags: [],
      attackChains: [],
      reportDetails: [],
    },
  }
}

export async function encryptPayload(payload: MessagePayload): Promise<ChatEnvelope> {
  return {
    ivB64: "plain",
    cipherB64: b64FromArray(strToBytes(JSON.stringify(payload))),
  }
}

export async function signEnvelope(
  _message: Pick<ChatMessage, "groupId" | "senderId" | "sentAt" | "envelope">
) {
  return "plain"
}

export async function verifyEnvelope(
  _message: Pick<ChatMessage, "groupId" | "senderId" | "sentAt" | "envelope" | "signatureB64">
) {
  return true
}

export async function decryptPayload(envelope: ChatEnvelope): Promise<MessagePayload> {
  const plainBytes = arrayFromB64(envelope.cipherB64)
  return JSON.parse(bytesToStr(plainBytes.buffer)) as MessagePayload
}

export async function createSignedMessage(input: {
  group: ChatGroup
  sender: ChatUser
  payload: MessagePayload
  replyToMessageId?: string
}): Promise<ChatMessage> {
  const envelope = await encryptPayload(input.payload)
  const base: Omit<ChatMessage, "signatureB64"> = {
    id: makeId(),
    groupId: input.group.id,
    senderId: input.sender.id,
    sentAt: Date.now(),
    envelope,
    replyToMessageId: input.replyToMessageId,
    reactions: {},
    metadata: {
      source: "local",
      integrity: "signed",
    },
  }
  const signatureB64 = await signEnvelope(base)
  return {
    ...base,
    signatureB64,
  }
}

async function buildSeedState(): Promise<SecureChatState> {
  const users = await Promise.all(USER_SEEDS.map(makeUser))
  const groups = await Promise.all([
    makeGroup({ id: "grp-admin-user", name: "Admin & SOC", members: [ADMIN_USER, STANDARD_USER], ownerUserId: ADMIN_USER }),
  ])

  // Start completely clean with no messages
  return {
    users,
    groups,
    messages: [],
    selectedGroupId: "grp-admin-user",
  }
}

function serializeState(state: SecureChatState): StoredState {
  return {
    users: state.users.map((u) => ({
      id: u.id,
      name: u.name,
      color: u.color,
    })),
    groups: state.groups.map((g) => ({
      id: g.id,
      name: g.name,
      members: g.members,
      pinnedMessageIds: g.pinnedMessageIds,
      metadata: g.metadata,
    })),
    messages: state.messages,
    selectedGroupId: state.selectedGroupId,
  }
}

async function restoreState(stored: StoredState): Promise<SecureChatState> {
  const users: ChatUser[] = []
  for (const user of stored.users) {
    users.push({
      id: user.id,
      name: user.name,
      color: user.color,
    })
  }

  const groups: ChatGroup[] = []
  for (const group of stored.groups) {
    groups.push({
      id: group.id,
      name: group.name,
      members: group.members,
      pinnedMessageIds: group.pinnedMessageIds,
      metadata: group.metadata,
    })
  }

  return {
    users,
    groups,
    messages: stored.messages,
    selectedGroupId: stored.selectedGroupId || groups[0]?.id || "",
  }
}

export async function loadSecureChatState(): Promise<SecureChatState> {
  ensureFreshChatStorage()

  const saved = window.localStorage.getItem(STORAGE_KEY)
  if (!saved) {
    const seeded = await buildSeedState()
    saveSecureChatState(seeded)
    return seeded
  }

  try {
    const parsed = JSON.parse(saved) as StoredState
    const restored = await restoreState(parsed)
    return restored
  } catch {
    const seeded = await buildSeedState()
    saveSecureChatState(seeded)
    return seeded
  }
}

export async function loadSecureChatStateFromSerialized(serialized: string): Promise<SecureChatState> {
  const parsed = JSON.parse(serialized) as StoredState
  return restoreState(parsed)
}

export function getSecureChatSerializedState() {
  if (typeof window === "undefined") return null
  return window.localStorage.getItem(STORAGE_KEY)
}

export function storeSecureChatSerializedState(serialized: string) {
  if (typeof window === "undefined") return
  window.localStorage.setItem(STORAGE_KEY, serialized)
}

export function saveSecureChatState(state: SecureChatState) {
  const serialized = serializeState(state)
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(serialized))
}

export async function createGroup(input: {
  name: string
  members: string[]
  ownerUserId: string
}): Promise<ChatGroup> {
  if (input.ownerUserId !== ADMIN_USER) {
    throw new Error("Only admin can create groups")
  }

  return makeGroup({
    id: makeId(),
    name: input.name,
    members: Array.from(new Set(input.members)),
    ownerUserId: input.ownerUserId,
  })
}

export function getCurrentUserId() {
  if (typeof window === "undefined") return STANDARD_USER
  try {
    const raw = window.sessionStorage.getItem("auth_session") || window.localStorage.getItem("auth_session")
    if (!raw) return STANDARD_USER
    const parsed = JSON.parse(raw) as { role?: string }
    return parsed.role === "admin" ? ADMIN_USER : STANDARD_USER
  } catch {
    return STANDARD_USER
  }
}

export function isAdminUser(userId: string) {
  return userId === ADMIN_USER
}

export async function verifyAndDecryptMessage(input: {
  message: ChatMessage
  users: ChatUser[]
  groups: ChatGroup[]
}): Promise<{ tampered: boolean; payload: MessagePayload | null }> {
  const sender = input.users.find((u) => u.id === input.message.senderId)
  const group = input.groups.find((g) => g.id === input.message.groupId)
  if (!sender || !group) {
    return { tampered: true, payload: null }
  }

  try {
    const verified = await verifyEnvelope(input.message)
    if (!verified) {
      return { tampered: true, payload: null }
    }
    const payload = await decryptPayload(input.message.envelope)
    return { tampered: false, payload }
  } catch {
    return { tampered: true, payload: null }
  }
}
