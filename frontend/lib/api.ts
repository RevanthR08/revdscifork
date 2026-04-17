// =============================================================================
// MOCK API — All data is served from static mock datasets (no backend required)
// All API routing / proxy calls have been removed.
// =============================================================================

import {
  getMockAnalysisList,
  getMockAnalysis,
  getMockEvents,
  getMockFindings,
  getMockChains,
  getMockSummary,
  getMockCategories,
  USER_CSV_TO_SCAN_ID,
} from "@/lib/mockData"

// Simulates a short async delay for realistic UX
const delay = (ms = 150) => new Promise(res => setTimeout(res, ms))

const FALLBACK_SCAN_ID = "mock-upload-id"

function normalizeScanId(scanId: string) {
  const raw = scanId.trim().toLowerCase()
  if (!raw) return ""

  const userMatch = raw.match(/^user[-_]?(\d{1,4})$/)
  if (userMatch) {
    const n = Number.parseInt(userMatch[1], 10)
    if (!Number.isNaN(n)) {
      return `user-${String(n).padStart(3, "0")}`
    }
  }

  const dsMatch = raw.match(/^ds[-_]?(\d{1,4})$/)
  if (dsMatch) {
    const n = Number.parseInt(dsMatch[1], 10)
    if (!Number.isNaN(n)) {
      return `ds-${String(n).padStart(3, "0")}`
    }
  }

  return raw
}

function resolveScanId(scanId: string) {
  if (getMockAnalysis(scanId)) {
    return scanId
  }

  const normalized = normalizeScanId(scanId)
  if (normalized && getMockAnalysis(normalized)) {
    return normalized
  }

  // If a user-specific ID is not preloaded, map it to ds-### where possible.
  const userMatch = normalized.match(/^user-(\d{3,4})$/)
  if (userMatch) {
    const datasetId = `ds-${String(Number.parseInt(userMatch[1], 10)).padStart(3, "0")}`
    if (getMockAnalysis(datasetId)) {
      return datasetId
    }
  }

  return FALLBACK_SCAN_ID
}

// Tracks which features have already been fully loaded for each scan ID in this session.
const cache = {
  analysis: new Set<string>(),
  findings: new Set<string>(),
  chains:   new Set<string>(),
  summary:  new Set<string>(),
}

/**
 * Returns a random delay between min and max seconds.
 */
function getRandomDelay(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1) + min) * 1000
}

/**
 * Handles simulated latency based on feature type and first-time access.
 */
async function simulateLatency(scanId: string, feature: keyof typeof cache, min: number, max: number, silent = false) {
  const resolvedId = resolveScanId(scanId)
  
  if (silent) {
    await delay(100)
    return
  }

  if (cache[feature].has(resolvedId)) {
    await delay(100)
    return
  }
  
  const ms = getRandomDelay(min, max)
  await delay(ms)
  cache[feature].add(resolvedId)
}

/**
 * LIST all analyses (previously: GET /scans)
 */
export async function listScans(_limit = 20, _offset = 0) {
  await delay()
  return { scans: getMockAnalysisList() }
}

/**
 * GET a single analysis by ID (previously: GET /scans/{id})
 */
export async function getScan(id: string, silent = false) {
  const resolvedId = resolveScanId(id)
  await simulateLatency(resolvedId, "analysis", 4, 8, silent)
  const analysis = getMockAnalysis(resolvedId)
  if (!analysis) throw new Error(`Analysis ${id} not found`)
  return analysis
}

/**
 * GET events for a scan (previously: GET /scans/{id}/events)
 */
export async function getScanEvents(id: string, params: { limit?: number; offset?: number; category?: string } = {}) {
  const resolvedId = resolveScanId(id)
  // Events are usually loaded with the main analysis or summary, keeping it light
  await delay(200)
  const allEvents = getMockEvents(resolvedId)
  const limited = allEvents.slice(params.offset || 0, (params.offset || 0) + (params.limit || allEvents.length))
  return { events: limited }
}

/**
 * GET categories for a scan (previously: GET /scans/{id}/categories)
 */
export async function getScanCategories(id: string) {
  const resolvedId = resolveScanId(id)
  await delay(100)
  return { categories: getMockCategories(resolvedId) }
}

/**
 * GET findings for a scan (previously: GET /scans/{id}/findings)
 */
export async function getScanFindings(id: string, silent = false) {
  const resolvedId = resolveScanId(id)
  await simulateLatency(resolvedId, "findings", 3, 5, silent)
  return { findings: getMockFindings(resolvedId) }
}

/**
 * GET attack chains (previously: GET /scans/{id}/chains)
 */
export async function getScanChains(id: string, silent = false) {
  const resolvedId = resolveScanId(id)
  await simulateLatency(resolvedId, "chains", 2, 4, silent)
  return { chains: getMockChains(resolvedId) }
}

/**
 * GET AI summary (previously: GET /scans/{id}/summary)
 */
export async function getScanSummary(id: string, silent = false) {
  const resolvedId = resolveScanId(id)
  await simulateLatency(resolvedId, "summary", 10, 15, silent)
  const summary = getMockSummary(resolvedId)
  if (!summary) throw new Error(`Summary for ${id} not found`)
  return summary
}

/**
 * STUB: DELETE (no-op in mock mode)
 */
export async function deleteAnalysis(_id: string) {
  await delay()
  return { success: true }
}

/**
 * Upload file — matches userXXXlogs.csv filenames to their enriched JSON dataset.
 * If the file name matches a known user dataset, the corresponding scan_id is
 * returned so the UI navigates directly to the rich pre-computed analysis.
 * Unknown files fall back to the generic mock-upload-id.
 */
export async function uploadFile(file: File) {
  await delay(1500)
  const matchedScanId = USER_CSV_TO_SCAN_ID[file.name] || USER_CSV_TO_SCAN_ID[file.name.toLowerCase()]
  return { 
    message: "Success", 
    scan_id: matchedScanId ? normalizeScanId(matchedScanId) : FALLBACK_SCAN_ID
  }
}

// Kept for backward compatibility (not used in mock mode)
export async function apiFetch(_path: string, _options?: RequestInit) {
  await delay()
  return {}
}

// WebSocket stubs (not needed in mock mode)
export function connectWebSocket(_analysisId: string, _onMessage: (data: any) => void) {
  return { close: () => {} } as any
}

export function connectSystemStatsWebSocket(_onMessage: (data: any) => void) {
  return { close: () => {} } as any
}

// travels stub for any pages that reference it
export async function getScanTravels(id: string, silent = false) {
  const resolvedId = resolveScanId(id)
  await delay()
  return { travels: [] }
}

