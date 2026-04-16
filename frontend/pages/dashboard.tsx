import { useState, useEffect } from "react"
import { useRouter } from "next/router"
import Link from "next/link"
import { motion } from "framer-motion"
import DashboardLayout from "@/components/layout/DashboardLayout"
import UploadZone from "@/components/dashboard/UploadZone"
import { Skeleton } from "@/components/dashboard/Skeletons"
import { CheckCircle, BarChart3, AlertTriangle, ShieldAlert, Link2 } from "lucide-react"
import { listScans } from "@/lib/api"
import { cn } from "@/lib/utils"

interface Analysis {
  scan_id: string
  file_name: string
  total_logs: number
  total_threats: number
  risk_score: number
  attack_chain_count: number
  generated_at: string
  status?: string
}

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

function countNonEmptyLines(text: string) {
  return text.split(/\r?\n/).filter((line) => line.trim().length > 0).length
}

function estimateLogsFromJson(parsed: unknown): number {
  if (Array.isArray(parsed)) return parsed.length
  if (!parsed || typeof parsed !== "object") return 0

  const record = parsed as Record<string, unknown>
  const candidateArrays = [record.logs, record.events, record.data, record.rows]
  for (const candidate of candidateArrays) {
    if (Array.isArray(candidate)) return candidate.length
  }

  return 0
}

async function estimateLogCount(file: File): Promise<number> {
  const lowerName = file.name.toLowerCase()
  const looksLikeJson = file.type.includes("json") || lowerName.endsWith(".json")
  const looksLikeCsv =
    file.type.includes("csv") || lowerName.endsWith(".csv") || lowerName.endsWith(".tsv")
  const looksLikeText =
    file.type.startsWith("text/") ||
    lowerName.endsWith(".txt") ||
    lowerName.endsWith(".log") ||
    lowerName.endsWith(".ndjson")

  if (looksLikeJson || looksLikeCsv || looksLikeText) {
    const text = await file.text()

    if (looksLikeJson) {
      try {
        const parsed = JSON.parse(text)
        const jsonCount = estimateLogsFromJson(parsed)
        if (jsonCount > 0) return jsonCount
      } catch {
        // fall back to line-based estimation
      }
    }

    const lines = countNonEmptyLines(text)
    if (looksLikeCsv && lines > 0) {
      return Math.max(0, lines - 1)
    }
    return Math.max(1, lines)
  }

  // Fallback for unknown/binary inputs: rough estimate by bytes per log entry.
  return Math.max(1, Math.round(file.size / 180))
}

function getDelayFromLogCount(logCount: number) {
  // 10k logs -> 10s, 20k logs -> 20s (linear at 1 log = 1ms)
  const ms = Math.round(logCount)
  return Math.min(120000, Math.max(1000, ms))
}

export default function DashboardPage() {
  const router = useRouter()
  const [analyses, setAnalyses] = useState<Analysis[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)

  useEffect(() => {
    loadAnalyses()
  }, [])

  const loadAnalyses = async () => {
    const startedAt = Date.now()
    const minimumLoadingMs = 2700

    try {
      const data = await listScans()
      setAnalyses(data.scans || [])
    } catch (err) {
      console.error("Failed to load analyses:", err)
    } finally {
      const elapsed = Date.now() - startedAt
      if (elapsed < minimumLoadingMs) {
        await new Promise((resolve) => setTimeout(resolve, minimumLoadingMs - elapsed))
      }
      setLoading(false)
    }
  }

  const handleUpload = async (file: File) => {
    setUploading(true)
    setUploadProgress(0)

    const estimatedLogs = await estimateLogCount(file)
    const simulatedDelayMs = getDelayFromLogCount(estimatedLogs)
    const progressStartedAt = Date.now()

    const interval = setInterval(() => {
      const elapsed = Date.now() - progressStartedAt
      const progress = Math.min(95, Math.round((elapsed / simulatedDelayMs) * 95))
      setUploadProgress((prev) => Math.max(prev, progress))
      if (progress >= 95) {
        clearInterval(interval)
      }
    }, 200)

    try {
      const { uploadFile } = await import("@/lib/api")
      const uploadPromise = uploadFile(file)

      await Promise.all([uploadPromise, wait(simulatedDelayMs)])
      const result = await uploadPromise

      setUploadProgress(100)
      clearInterval(interval)

      if (result.scan_id) {
        setTimeout(() => {
          router.push(`/analysis/${result.scan_id}`)
        }, 800)
      }
    } catch (err: any) {
      alert(`Upload failed: ${err.message}`)
      setUploading(false)
      clearInterval(interval)
    }
  }

  const getRiskColor = (score: number) => {
    const pct = Math.round(score / 100)
    if (pct >= 80) return "text-red-400"
    if (pct >= 60) return "text-orange-400"
    if (pct >= 40) return "text-yellow-400"
    return "text-green-400"
  }

  const getRiskBadge = (score: number) => {
    const pct = Math.round(score / 100)
    if (pct >= 80) return { label: "CRITICAL", className: "bg-red-500" }
    if (pct >= 60) return { label: "HIGH", className: "bg-orange-500" }
    if (pct >= 40) return { label: "MEDIUM", className: "bg-yellow-500" }
    return { label: "LOW", className: "bg-green-500" }
  }

  const DatasetRowSkeleton = () => (
    <div className="bg-zinc-900 border border-zinc-800 rounded-md p-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:gap-4">
        <Skeleton className="w-10 h-10 rounded-md shrink-0" />

        <div className="flex-1 min-w-0 space-y-2">
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-56 max-w-full" />
            <Skeleton className="h-4 w-16 rounded-full" />
          </div>
          <Skeleton className="h-3 w-40 max-w-full" />
        </div>

        <div className="w-full flex items-center justify-between gap-4 md:w-auto md:justify-start md:gap-6">
          <div className="text-right space-y-1">
            <Skeleton className="h-4 w-10 ml-auto" />
            <Skeleton className="h-3 w-8 ml-auto" />
          </div>

          <div className="text-right space-y-1">
            <Skeleton className="h-4 w-12 ml-auto" />
            <Skeleton className="h-3 w-8 ml-auto" />
          </div>

          <div className="text-right space-y-1">
            <Skeleton className="h-4 w-10 ml-auto" />
            <Skeleton className="h-3 w-8 ml-auto" />
          </div>

          <Skeleton className="w-6 h-6 rounded-full" />
        </div>
      </div>
    </div>
  )

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Dashboard</h1>
            <p className="text-sm text-zinc-400 mt-1">
              AI-powered threat analysis
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-[1.7fr_0.8fr] gap-4 items-stretch">
          <UploadZone onUpload={handleUpload} uploading={uploading} progress={uploadProgress} />
          <div className="bg-zinc-900 border border-zinc-800 rounded-md p-5 flex flex-col justify-between">
            <div>
              <div className="inline-flex w-10 h-10 items-center justify-center rounded-md bg-[#3b3486]/20 mb-3">
                <Link2 className="w-5 h-5 text-[#b9b2ff]" />
              </div>
              <p className="text-xs uppercase tracking-wider text-zinc-500">Connector Pipeline v4.2</p>
              <h3 className="mt-1 text-lg font-bold text-white">Integrations & Connectors</h3>
              <p className="mt-2 text-sm text-zinc-400 leading-relaxed">
                Configure SIEM/IDS webhooks and cryptographic chain of custody for tamper-proof evidence flow.
              </p>
            </div>
            <Link
              href="/connectors"
              className="mt-5 inline-flex items-center justify-center rounded-md bg-[#3b3486] px-4 py-2 text-sm font-semibold text-white hover:bg-[#4a439b]"
            >
              Open Connectors Page
            </Link>
          </div>
        </div>

        {!loading && analyses.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="bg-zinc-900 border border-zinc-800 p-4 flex items-center gap-3 rounded-md">
              <div className="w-10 h-10 flex items-center justify-center bg-blue-500/10 rounded-md">
                <BarChart3 className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <p className="text-xl font-bold text-white">{analyses.reduce((s, a) => s + a.total_logs, 0).toLocaleString()}</p>
                <p className="text-xs text-zinc-500">Total Logs Analyzed</p>
              </div>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 p-4 flex items-center gap-3 rounded-md">
              <div className="w-10 h-10 flex items-center justify-center bg-orange-500/10 rounded-md">
                <AlertTriangle className="w-5 h-5 text-orange-400" />
              </div>
              <div>
                <p className="text-xl font-bold text-white">{analyses.reduce((s, a) => s + a.total_threats, 0)}</p>
                <p className="text-xs text-zinc-500">Total Threats Found</p>
              </div>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 p-4 flex items-center gap-3 rounded-md">
              <div className="w-10 h-10 flex items-center justify-center bg-red-500/10 rounded-md">
                <ShieldAlert className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="text-xl font-bold text-white">{analyses.filter((a) => Math.round(a.risk_score / 100) >= 80).length}</p>
                <p className="text-xs text-zinc-500">Critical Risk Datasets</p>
              </div>
            </div>
          </motion.div>
        )}

        <div>
          <h2 className="text-sm font-bold text-white mb-4">Pre-Loaded Analysis Datasets</h2>

          {loading ? (
            <div className="space-y-3 bg-zinc-900 border border-zinc-800 rounded-md p-4">
              <div className="grid gap-3">
                <Skeleton className="h-4 w-56" />
                <Skeleton className="h-3 w-72 max-w-full" />
              </div>
              <div className="space-y-3 pt-2">
                <DatasetRowSkeleton />
                <DatasetRowSkeleton />
                <DatasetRowSkeleton />
              </div>
            </div>
          ) : analyses.length === 0 ? (
            <div className="text-center py-12 bg-zinc-900 border border-zinc-800 rounded-md">
              <BarChart3 className="w-10 h-10 text-zinc-600 mx-auto mb-3" />
              <p className="text-sm text-zinc-400">No datasets found.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {analyses.map((analysis, index) => {
                const riskPct = Math.round(analysis.risk_score / 100)
                const badge = getRiskBadge(analysis.risk_score)

                return (
                  <motion.div
                    key={analysis.scan_id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.04 }}
                    onClick={() => router.push(`/analysis/${analysis.scan_id}`)}
                    className="bg-zinc-900 border border-zinc-800 rounded-md p-4 cursor-pointer hover:border-zinc-600 transition-all duration-150 group"
                  >
                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:gap-4">
                      <div className="w-10 h-10 flex items-center justify-center bg-green-500/10 rounded-md">
                        <CheckCircle className="w-5 h-5 text-green-400" />
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <p className="text-sm font-medium text-white truncate group-hover:text-purple-300 transition-colors">{analysis.file_name}</p>
                          <span className={cn("text-[9px] font-bold px-1.5 py-0.5 text-white shrink-0 rounded", badge.className)}>
                            {badge.label}
                          </span>
                        </div>
                        <p className="text-xs text-zinc-500">
                          {analysis.total_logs.toLocaleString()} logs - {" "}
                          {new Date(analysis.generated_at).toLocaleDateString("en-US", {
                            year: "numeric", month: "short", day: "numeric"
                          })}
                        </p>
                      </div>

                      <div className="w-full flex items-center justify-between gap-4 md:w-auto md:justify-start md:gap-6">
                        <div className="text-right">
                          <div className="flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                            <span className="text-sm font-medium text-white">{analysis.total_threats}</span>
                          </div>
                          <p className="text-[10px] text-zinc-500">threats</p>
                        </div>

                        <div className="text-right">
                          <span className={cn("text-sm font-bold", getRiskColor(analysis.risk_score))}>{riskPct}%</span>
                          <p className="text-[10px] text-zinc-500">risk</p>
                        </div>

                        <div className="text-right">
                          <span className="text-sm font-medium text-blue-400">{analysis.attack_chain_count}</span>
                          <p className="text-[10px] text-zinc-500">chains</p>
                        </div>

                        <div className="w-6 h-6 flex items-center justify-center text-zinc-600 group-hover:text-zinc-300 transition-colors">
                          <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                            <path d="M2 6h8M7 3l3 3-3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" fill="none" />
                          </svg>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  )
}
