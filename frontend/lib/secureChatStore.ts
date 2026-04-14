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
  signPrivate: CryptoKey
  signPublic: CryptoKey
  signPrivateJwk: JsonWebKey
  signPublicJwk: JsonWebKey
}

export type ChatGroup = {
  id: string
  name: string
  members: string[]
  key: CryptoKey
  keyJwk: JsonWebKey
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
  signPrivateJwk: JsonWebKey
  signPublicJwk: JsonWebKey
}

type StoredGroup = {
  id: string
  name: string
  members: string[]
  keyJwk: JsonWebKey
  pinnedMessageIds: string[]
  metadata: GroupMetadata
}

type StoredState = {
  users: StoredUser[]
  groups: StoredGroup[]
  messages: ChatMessage[]
  selectedGroupId: string
}

const STORAGE_KEY = "secure_chat_state_v1"

const CURRENT_USER = "u-me"
const USER_SEEDS = [
  { id: CURRENT_USER, name: "You", color: "bg-violet-500/30 text-violet-300" },
  { id: "u-ana", name: "Ananya", color: "bg-sky-500/30 text-sky-300" },
  { id: "u-raj", name: "Raj", color: "bg-emerald-500/30 text-emerald-300" },
  { id: "u-mila", name: "Mila", color: "bg-amber-500/30 text-amber-300" },
]

const strToBytes = (value: string) => new TextEncoder().encode(value)
const bytesToStr = (value: ArrayBuffer) => new TextDecoder().decode(value)

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
  const arr = new Uint8Array(6)
  window.crypto.getRandomValues(arr)
  return `id-${Date.now()}-${Array.from(arr).map((x) => x.toString(16).padStart(2, "0")).join("")}`
}

async function generateSigningKeys() {
  return window.crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  )
}

async function generateGroupKey() {
  return window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  )
}

async function makeUser(seed: { id: string; name: string; color: string }): Promise<ChatUser> {
  const pair = await generateSigningKeys()
  const signPrivateJwk = await window.crypto.subtle.exportKey("jwk", pair.privateKey)
  const signPublicJwk = await window.crypto.subtle.exportKey("jwk", pair.publicKey)

  return {
    id: seed.id,
    name: seed.name,
    color: seed.color,
    signPrivate: pair.privateKey,
    signPublic: pair.publicKey,
    signPrivateJwk,
    signPublicJwk,
  }
}

async function makeGroup(input: { id: string; name: string; members: string[]; ownerUserId: string }): Promise<ChatGroup> {
  const key = await generateGroupKey()
  const keyJwk = await window.crypto.subtle.exportKey("jwk", key)
  return {
    id: input.id,
    name: input.name,
    members: input.members,
    key,
    keyJwk,
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

export async function encryptPayload(payload: MessagePayload, key: CryptoKey): Promise<ChatEnvelope> {
  const iv = new Uint8Array(12)
  window.crypto.getRandomValues(iv)
  const plain = strToBytes(JSON.stringify(payload))
  const cipher = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain)

  return {
    ivB64: b64FromArray(iv),
    cipherB64: b64FromArray(new Uint8Array(cipher)),
  }
}

export async function signEnvelope(
  message: Pick<ChatMessage, "groupId" | "senderId" | "sentAt" | "envelope">,
  privateKey: CryptoKey
) {
  const signedText = `${message.groupId}.${message.senderId}.${message.sentAt}.${message.envelope.ivB64}.${message.envelope.cipherB64}`
  const sig = await window.crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: "SHA-256",
    },
    privateKey,
    strToBytes(signedText)
  )
  return b64FromArray(new Uint8Array(sig))
}

export async function verifyEnvelope(
  message: Pick<ChatMessage, "groupId" | "senderId" | "sentAt" | "envelope" | "signatureB64">,
  publicKey: CryptoKey
) {
  const signedText = `${message.groupId}.${message.senderId}.${message.sentAt}.${message.envelope.ivB64}.${message.envelope.cipherB64}`
  return window.crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: "SHA-256",
    },
    publicKey,
    arrayFromB64(message.signatureB64),
    strToBytes(signedText)
  )
}

export async function decryptPayload(envelope: ChatEnvelope, key: CryptoKey): Promise<MessagePayload> {
  const iv = arrayFromB64(envelope.ivB64)
  const cipher = arrayFromB64(envelope.cipherB64)
  const plain = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)
  return JSON.parse(bytesToStr(plain)) as MessagePayload
}

export async function createSignedMessage(input: {
  group: ChatGroup
  sender: ChatUser
  payload: MessagePayload
  replyToMessageId?: string
}): Promise<ChatMessage> {
  const envelope = await encryptPayload(input.payload, input.group.key)
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
  const signatureB64 = await signEnvelope(base, input.sender.signPrivate)
  return {
    ...base,
    signatureB64,
  }
}

async function buildSeedState(): Promise<SecureChatState> {
  const users = await Promise.all(USER_SEEDS.map(makeUser))
  const groups = await Promise.all([
    makeGroup({ id: "grp-incidents", name: "Incident Response", members: [CURRENT_USER, "u-ana", "u-raj"], ownerUserId: CURRENT_USER }),
    makeGroup({ id: "grp-threat-intel", name: "Threat Intel", members: [CURRENT_USER, "u-ana", "u-mila"], ownerUserId: CURRENT_USER }),
  ])

  const ana = users.find((u) => u.id === "u-ana")
  const mila = users.find((u) => u.id === "u-mila")
  const incidents = groups.find((g) => g.id === "grp-incidents")
  const intel = groups.find((g) => g.id === "grp-threat-intel")

  if (!ana || !mila || !incidents || !intel) {
    return { users, groups, messages: [], selectedGroupId: groups[0]?.id || "" }
  }

  const msg1 = await createSignedMessage({
    group: incidents,
    sender: ana,
    payload: { text: "Team, lateral movement detected. Validate host isolation in Segment-2." },
  })
  msg1.sentAt = Date.now() - 1000 * 60 * 8
  msg1.signatureB64 = await signEnvelope(msg1, ana.signPrivate)

  const msg2 = await createSignedMessage({
    group: intel,
    sender: mila,
    payload: { text: "IOC package uploaded. Reviewing Suricata correlation now." },
  })
  msg2.sentAt = Date.now() - 1000 * 60 * 3
  msg2.signatureB64 = await signEnvelope(msg2, mila.signPrivate)

  return {
    users,
    groups,
    messages: [msg1, msg2],
    selectedGroupId: "grp-incidents",
  }
}

function serializeState(state: SecureChatState): StoredState {
  return {
    users: state.users.map((u) => ({
      id: u.id,
      name: u.name,
      color: u.color,
      signPrivateJwk: u.signPrivateJwk,
      signPublicJwk: u.signPublicJwk,
    })),
    groups: state.groups.map((g) => ({
      id: g.id,
      name: g.name,
      members: g.members,
      keyJwk: g.keyJwk,
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
    const signPrivate = await window.crypto.subtle.importKey(
      "jwk",
      user.signPrivateJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
    )
    const signPublic = await window.crypto.subtle.importKey(
      "jwk",
      user.signPublicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    )
    users.push({
      id: user.id,
      name: user.name,
      color: user.color,
      signPrivate,
      signPublic,
      signPrivateJwk: user.signPrivateJwk,
      signPublicJwk: user.signPublicJwk,
    })
  }

  const groups: ChatGroup[] = []
  for (const group of stored.groups) {
    const key = await window.crypto.subtle.importKey("jwk", group.keyJwk, { name: "AES-GCM" }, true, ["encrypt", "decrypt"])
    groups.push({
      id: group.id,
      name: group.name,
      members: group.members,
      key,
      keyJwk: group.keyJwk,
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

export function saveSecureChatState(state: SecureChatState) {
  const serialized = serializeState(state)
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(serialized))
}

export async function createGroup(input: {
  name: string
  members: string[]
  ownerUserId: string
}): Promise<ChatGroup> {
  return makeGroup({
    id: makeId(),
    name: input.name,
    members: Array.from(new Set(input.members)),
    ownerUserId: input.ownerUserId,
  })
}

export function getCurrentUserId() {
  return CURRENT_USER
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
    const verified = await verifyEnvelope(input.message, sender.signPublic)
    if (!verified) {
      return { tampered: true, payload: null }
    }
    const payload = await decryptPayload(input.message.envelope, group.key)
    return { tampered: false, payload }
  } catch {
    return { tampered: true, payload: null }
  }
}
