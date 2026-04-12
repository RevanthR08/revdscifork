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
} from "@/lib/mockData"

// Simulates a short async delay for realistic UX
const delay = (ms = 150) => new Promise(res => setTimeout(res, ms))

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
  await delay()
  const analysis = getMockAnalysis(id)
  if (!analysis) throw new Error(`Analysis ${id} not found`)
  return analysis
}

/**
 * GET events for a scan (previously: GET /scans/{id}/events)
 */
export async function getScanEvents(id: string, params: { limit?: number; offset?: number; category?: string } = {}) {
  await delay()
  const allEvents = getMockEvents(id)
  const limited = allEvents.slice(params.offset || 0, (params.offset || 0) + (params.limit || allEvents.length))
  return { events: limited }
}

/**
 * GET categories for a scan (previously: GET /scans/{id}/categories)
 */
export async function getScanCategories(id: string) {
  await delay()
  return { categories: getMockCategories(id) }
}

/**
 * GET findings for a scan (previously: GET /scans/{id}/findings)
 */
export async function getScanFindings(id: string) {
  await delay()
  return { findings: getMockFindings(id) }
}

/**
 * GET attack chains (previously: GET /scans/{id}/chains)
 */
export async function getScanChains(id: string) {
  await delay()
  return { chains: getMockChains(id) }
}

/**
 * GET AI summary (previously: GET /scans/{id}/summary)
 */
export async function getScanSummary(id: string) {
  await delay(600) // Slightly longer to simulate AI generation
  const summary = getMockSummary(id)
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
 * STUB: Upload file (MOCK mode handles the upload by returning a pre-defined ID)
 */
export async function uploadFile(_file: File) {
  await delay(1500)
  return { 
    message: "Success", 
    scan_id: "mock-upload-id" 
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
