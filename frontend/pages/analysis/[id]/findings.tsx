import { useState, useEffect } from "react"
import { useRouter } from "next/router"
import { motion } from "framer-motion"
import { AlertTriangle, Filter, X } from "lucide-react"
import DashboardLayout from "@/components/layout/DashboardLayout"
import SeverityStats from "@/components/dashboard/SeverityStats"
import FindingCard from "@/components/dashboard/findings/FindingCard"
import Pagination from "@/components/dashboard/Pagination"
import EmptyState from "@/components/dashboard/EmptyState"
import { FindingsPageSkeleton } from "@/components/dashboard/Skeletons"
import { getScanFindings, getScanCategories } from "@/lib/api"

interface Category {
  category_id?: string
  category_name: string
  mitre_id?: string
  tactic?: string
  risk_score: number
  event_count: number
  ai_summary?: string
}

interface Finding {
  id: string
  severity: string
  title: string
  description?: string
  detection_type: string
  rule_id?: string
  mitre_techniques?: string[]
  mitre_ids?: string[]
  mitre_tactics?: string[]
  affected_users?: string[]
  affected_hosts?: string[]
  source_ips?: string[]
  anomaly_score?: number
  ml_method?: string
  details?: Record<string, any>
  timestamp_start?: string
  timestamp_end?: string
}

// Map a category's risk_score (1-10) → severity label
function riskToSeverity(score: number): string {
  if (score >= 9) return "critical"
  if (score >= 7) return "high"
  if (score >= 4) return "medium"
  if (score >= 2) return "low"
  return "info"
}

// Map detection_type filter → category name keywords
const TYPE_CATEGORY_MAP: Record<string, string[]> = {
  ml_anomaly: ["anomaly", "ml", "isolation", "statistical"],
  impossible_travel: ["travel", "impossible"],
  rule: ["brute force", "privilege", "lateral", "ransomware", "log tamper", "persist", "network", "exec"],
}

export default function FindingsPage() {
  const router = useRouter()
  const { id } = router.query

  // All categories from backend (used for stats + category→severity map)
  const [categories, setCategories] = useState<Category[]>([])
  // All events loaded (full list for client-side filter)
  const [allFindings, setAllFindings] = useState<Finding[]>([])
  // Filtered subset displayed
  const [findings, setFindings] = useState<Finding[]>([])

  const [bySeverity, setBySeverity] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [filterSeverity, setFilterSeverity] = useState("")
  const [filterType, setFilterType] = useState("")
  const [totalFindings, setTotalFindings] = useState(0)

  const ITEMS_PER_PAGE = 20

  // Build a map: category_name (lowercase) → severity
  const buildCategoryMap = (cats: Category[]) => {
    const map: Record<string, string> = {}
    cats.forEach(cat => {
      map[cat.category_name.toLowerCase()] = riskToSeverity(cat.risk_score)
    })
    return map
  }

  // Load findings from mock data
  useEffect(() => {
    if (!id) return
    const scanId = id as string
    setLoading(true)

    Promise.all([
      getScanCategories(scanId),
      getScanFindings(scanId),
    ])
      .then(([catData, findingsData]) => {
        const cats: Category[] = (catData.categories || []).map((c: any) => ({
          category_name: c.tactic || "Unknown",
          risk_score: c.risk_score || 5,
          event_count: c.event_count || 0,
          tactic: c.tactic,
        }))
        setCategories(cats)

        // Build severity totals — count each finding as 1 individual finding
        const sevMap: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        ;(findingsData.findings || []).forEach((f: any) => {
          const sev = f.severity || "info"
          sevMap[sev] = (sevMap[sev] || 0) + 1
        })
        setBySeverity(sevMap)

        // Map mock findings to Finding interface with all fields
        const mapped: Finding[] = (findingsData.findings || []).map((f: any) => ({
          id: f.id,
          severity: f.severity,
          title: f.title,
          description: f.description,
          detection_type: f.detection_type,
          rule_id: f.rule_id,
          mitre_techniques: f.mitre_techniques || [],
          mitre_ids: f.mitre_ids || [],
          mitre_tactics: f.mitre_tactics || [],
          affected_users: f.affected_users || [],
          affected_hosts: f.affected_hosts || [],
          timestamp_start: f.timestamp,
          details: {
            count: f.count,
            rule_id: f.rule_id,
            mitre_ids: f.mitre_ids,
            detection_type: f.detection_type,
          },
        }))

        setAllFindings(mapped)
        setTotalFindings(mapped.length)
      })
      .catch(err => console.error("Failed to load findings:", err))
      .finally(() => setLoading(false))
  }, [id])

  // Client-side filtering + pagination whenever filters or allFindings change
  useEffect(() => {
    let filtered = [...allFindings]

    if (filterSeverity) {
      filtered = filtered.filter(f => f.severity === filterSeverity)
    }

    if (filterType) {
      filtered = filtered.filter(f => f.detection_type === filterType)
    }

    setTotalFindings(filtered.length)
    setTotalPages(Math.max(1, Math.ceil(filtered.length / ITEMS_PER_PAGE)))

    const start = (page - 1) * ITEMS_PER_PAGE
    setFindings(filtered.slice(start, start + ITEMS_PER_PAGE))
  }, [allFindings, filterSeverity, filterType, page])

  const handleFilterChange = (type: "severity" | "type", value: string) => {
    setPage(1)
    if (type === "severity") setFilterSeverity(value)
    else setFilterType(value)
  }

  const clearFilters = () => {
    setPage(1)
    setFilterSeverity("")
    setFilterType("")
  }

  const hasFilters = filterSeverity || filterType

  if (loading) {
    return (
      <DashboardLayout analysisId={id as string}>
        <FindingsPageSkeleton />
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout analysisId={id as string}>
      <div className="space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-orange-500/10 flex items-center justify-center" style={{ borderRadius: "6px" }}>
              <AlertTriangle className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Findings</h1>
              <p className="text-xs text-zinc-500">
                {totalFindings} detections identified
                {hasFilters && <span className="ml-1 text-orange-400">(filtered)</span>}
              </p>
            </div>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 text-xs text-zinc-500">
              <Filter className="w-3.5 h-3.5" />
              Filter:
            </div>

            <select
              value={filterSeverity}
              onChange={(e) => handleFilterChange("severity", e.target.value)}
              className="bg-zinc-800 border border-zinc-700 text-sm text-zinc-300 px-3 py-1.5 outline-none focus:border-zinc-600 transition-colors cursor-pointer"
              style={{ borderRadius: "4px" }}
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>

            <select
              value={filterType}
              onChange={(e) => handleFilterChange("type", e.target.value)}
              className="bg-zinc-800 border border-zinc-700 text-sm text-zinc-300 px-3 py-1.5 outline-none focus:border-zinc-600 transition-colors cursor-pointer"
              style={{ borderRadius: "4px" }}
            >
              <option value="">All Types</option>
              <option value="rule">Rule-Based</option>
              <option value="ml_anomaly">ML Anomaly</option>
            </select>

            {hasFilters && (
              <button
                onClick={clearFilters}
                className="flex items-center gap-1 text-xs text-zinc-400 hover:text-red-400 px-2 py-1.5 hover:bg-red-500/10 transition-colors"
                style={{ borderRadius: "4px" }}
              >
                <X className="w-3 h-3" />
                Clear
              </button>
            )}
          </div>
        </motion.div>

        {/* Severity Stats — always shows totals from categories, never changes with filter */}
        <SeverityStats stats={bySeverity} />

        {/* Findings List */}
        {findings.length === 0 ? (
          <EmptyState type={hasFilters ? "no-results" : "no-findings"} />
        ) : (
          <div className="space-y-3">
            {findings.map((finding, index) => (
              <FindingCard key={finding.id} finding={finding} index={index} />
            ))}
          </div>
        )}

        {/* Pagination */}
        <Pagination
          currentPage={page}
          totalPages={totalPages}
          onPageChange={setPage}
        />
      </div>
    </DashboardLayout>
  )
}
