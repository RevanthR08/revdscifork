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

// Tracks which scan IDs have already been fully loaded this session.
// Once a scan is in this set, all subsequent API calls for it return instantly
// so navigating between Overview / AI Summary / Attack Chains never re-triggers the loading animation.
const loadedScanCache = new Set<string>()

async function delayForDataset(scanId: string, _multiplier = 1) {
  const resolvedScanId = resolveScanId(scanId)
  // Skip delay on subsequent visits to the same scan — instant navigation
  if (loadedScanCache.has(resolvedScanId)) {
    await delay(50)
    return
  }
  // First load: fixed 3-second delay to simulate AI scanning
  await delay(3000)
}

// Mark a scan as fully loaded so future calls skip the delay
function markScanLoaded(scanId: string) {
  loadedScanCache.add(resolveScanId(scanId))
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
export async function getScan(id: string) {
  const resolvedId = resolveScanId(id)
  await delayForDataset(resolvedId, 1)
  const analysis = getMockAnalysis(resolvedId)
  if (!analysis) throw new Error(`Analysis ${id} not found`)
  // Mark this scan as loaded — all further calls for this ID will be instant
  markScanLoaded(resolvedId)
  return analysis
}

/**
 * GET events for a scan (previously: GET /scans/{id}/events)
 */
export async function getScanEvents(id: string, params: { limit?: number; offset?: number; category?: string } = {}) {
  const resolvedId = resolveScanId(id)
  await delayForDataset(resolvedId, 0.85)
  const allEvents = getMockEvents(resolvedId)
  const limited = allEvents.slice(params.offset || 0, (params.offset || 0) + (params.limit || allEvents.length))
  return { events: limited }
}

/**
 * GET categories for a scan (previously: GET /scans/{id}/categories)
 */
export async function getScanCategories(id: string) {
  const resolvedId = resolveScanId(id)
  await delayForDataset(resolvedId, 0.35)
  return { categories: getMockCategories(resolvedId) }
}

/**
 * GET findings for a scan (previously: GET /scans/{id}/findings)
 */
export async function getScanFindings(id: string) {
  const resolvedId = resolveScanId(id)
  await delayForDataset(resolvedId, 0.7)
  markScanLoaded(resolvedId)
  return { findings: getMockFindings(resolvedId) }
}

/**
 * GET attack chains (previously: GET /scans/{id}/chains)
 */
export async function getScanChains(id: string) {
  const resolvedId = resolveScanId(id)
  await delayForDataset(resolvedId, 0.45)
  markScanLoaded(resolvedId)
  return { chains: getMockChains(resolvedId) }
}

/**
 * GET AI summary (previously: GET /scans/{id}/summary)
 */
export async function getScanSummary(id: string) {
  const resolvedId = resolveScanId(id)
  await delayForDataset(resolvedId, 1.15) // Slightly longer to simulate AI generation
  markScanLoaded(resolvedId)
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
export async function getScanTravels(_id: string) {
  await delay()
  return { travels: [] }
}
