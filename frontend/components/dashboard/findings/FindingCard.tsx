import React, { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  ChevronDown, Clock, User, Server, Globe, ExternalLink,
  Shield, Activity, Terminal, AlertTriangle, CheckCircle, Info
} from "lucide-react"
import { cn } from "@/lib/utils"

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

interface FindingCardProps {
  finding: Finding
  index: number
}

const severityConfig: Record<string, {
  color: string; bg: string; border: string; leftBar: string;
  badgeBg: string; icon: React.ReactNode
}> = {
  critical: {
    color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/30",
    leftBar: "bg-red-500", badgeBg: "bg-red-500/20 text-red-300 border border-red-500/40",
    icon: <AlertTriangle className="w-3.5 h-3.5" />,
  },
  high: {
    color: "text-orange-400", bg: "bg-orange-500/5", border: "border-orange-500/25",
    leftBar: "bg-orange-500", badgeBg: "bg-orange-500/20 text-orange-300 border border-orange-500/40",
    icon: <AlertTriangle className="w-3.5 h-3.5" />,
  },
  medium: {
    color: "text-yellow-400", bg: "bg-yellow-500/5", border: "border-yellow-500/20",
    leftBar: "bg-yellow-500", badgeBg: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40",
    icon: <Info className="w-3.5 h-3.5" />,
  },
  low: {
    color: "text-blue-400", bg: "bg-blue-500/5", border: "border-blue-500/20",
    leftBar: "bg-blue-500", badgeBg: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
    icon: <Info className="w-3.5 h-3.5" />,
  },
  info: {
    color: "text-zinc-400", bg: "bg-zinc-500/5", border: "border-zinc-700",
    leftBar: "bg-zinc-600", badgeBg: "bg-zinc-700 text-zinc-300 border border-zinc-600",
    icon: <CheckCircle className="w-3.5 h-3.5" />,
  },
}

const typeConfig: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  rule: { label: "Rule-Based", color: "text-purple-400 bg-purple-500/10 border border-purple-500/20", icon: <Shield className="w-3 h-3" /> },
  ml_anomaly: { label: "ML Anomaly", color: "text-cyan-400 bg-cyan-500/10 border border-cyan-500/20", icon: <Activity className="w-3 h-3" /> },
  impossible_travel: { label: "Geo Anomaly", color: "text-pink-400 bg-pink-500/10 border border-pink-500/20", icon: <Globe className="w-3 h-3" /> },
}

function MetaChip({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5 bg-zinc-800/70 border border-zinc-700/50 px-2.5 py-1.5 rounded-md">
      <span className="text-zinc-500">{icon}</span>
      <span className="text-[10px] text-zinc-500 uppercase tracking-wider">{label}</span>
      <span className="text-xs text-zinc-200 font-medium ml-0.5">{value}</span>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-[9px] font-bold text-zinc-600 uppercase tracking-widest mb-2">{title}</p>
      {children}
    </div>
  )
}

export default function FindingCard({ finding, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false)
  const sev = severityConfig[finding.severity] || severityConfig.info
  const typeInfo = typeConfig[finding.detection_type] || typeConfig.rule

  const formatTime = (ts?: string) => {
    if (!ts) return "—"
    try {
      const d = new Date(ts)
      return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    } catch { return ts }
  }

  const formatDate = (ts?: string) => {
    if (!ts) return ""
    try {
      return new Date(ts).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
    } catch { return "" }
  }

  // Parse description to extract structured fields
  const extractField = (desc: string, label: string): string | null => {
    const regex = new RegExp(`${label}:\\s*([^.]+)`)
    const match = desc?.match(regex)
    return match ? match[1].trim() : null
  }

  const process = extractField(finding.description || "", "Process")
  const eventId = extractField(finding.description || "", "Event ID")
  const cpu = extractField(finding.description || "", "CPU")
  const mem = extractField(finding.description || "", "Mem")
  const netIo = extractField(finding.description || "", "Net I/O")

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, delay: index * 0.02 }}
      className={cn(
        "relative bg-zinc-900 border transition-all duration-200 overflow-hidden",
        expanded ? sev.border : "border-zinc-800 hover:border-zinc-700",
      )}
      style={{ borderRadius: "8px" }}
    >
      {/* Severity left bar */}
      <div className={cn("absolute left-0 top-0 bottom-0 w-0.5", sev.leftBar)} />

      {/* ── Main clickable row ── */}
      <div
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-3 pl-4 pr-4 py-3.5 cursor-pointer"
      >
        {/* Severity badge */}
        <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider flex-shrink-0 rounded-md", sev.badgeBg)}>
          {sev.icon}
          {finding.severity}
        </span>

        {/* Title + meta */}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-white truncate">{finding.title}</p>
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            {finding.rule_id && (
              <span className="text-[10px] text-zinc-600 font-mono">{finding.rule_id}</span>
            )}
            {finding.mitre_ids?.slice(0, 2).map(t => (
              <span key={t} className="text-[10px] text-blue-400 font-mono bg-blue-500/10 px-1.5 py-0.5 rounded">{t}</span>
            ))}
            <span className="flex items-center gap-1 text-[10px] text-zinc-600">
              <Clock className="w-2.5 h-2.5" />
              {formatTime(finding.timestamp_start)} · {formatDate(finding.timestamp_start)}
            </span>
          </div>
        </div>

        {/* Detection type */}
        <span className={cn("flex items-center gap-1 text-[10px] px-2 py-1 rounded-md font-medium flex-shrink-0", typeInfo.color)}>
          {typeInfo.icon}
          {typeInfo.label}
        </span>

        {/* Chevron */}
        <motion.div animate={{ rotate: expanded ? 180 : 0 }} transition={{ duration: 0.2 }} className="flex-shrink-0">
          <ChevronDown className="w-4 h-4 text-zinc-600" />
        </motion.div>
      </div>

      {/* ── Expanded body ── */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 border-t border-zinc-800/80 pt-4 space-y-5">

              {/* Description */}
              {finding.description && (
                <Section title="Description">
                  <p className="text-sm text-zinc-300 leading-relaxed bg-zinc-800/30 border border-zinc-800 rounded-md px-3 py-2.5">
                    {finding.description}
                  </p>
                </Section>
              )}

              {/* Metric chips row */}
              {(process || cpu || mem || netIo || eventId) && (
                <Section title="Forensic Metrics">
                  <div className="flex flex-wrap gap-2">
                    {process && <MetaChip icon={<Terminal className="w-3 h-3" />} label="Process" value={process} />}
                    {eventId && <MetaChip icon={<Shield className="w-3 h-3" />} label="Event ID" value={eventId} />}
                    {cpu && <MetaChip icon={<Activity className="w-3 h-3" />} label="CPU" value={cpu} />}
                    {mem && <MetaChip icon={<Activity className="w-3 h-3" />} label="Memory" value={mem} />}
                    {netIo && <MetaChip icon={<Globe className="w-3 h-3" />} label="Net I/O" value={netIo} />}
                  </div>
                </Section>
              )}

              {/* Affected Entities */}
              <div className="grid grid-cols-2 gap-4">
                {finding.affected_users && finding.affected_users.length > 0 && (
                  <Section title={`Affected Users (${finding.affected_users.length})`}>
                    <div className="flex flex-wrap gap-1.5">
                      {finding.affected_users.map(u => (
                        <span key={u} className="flex items-center gap-1 text-xs text-zinc-300 bg-zinc-800 border border-zinc-700 px-2 py-1 rounded-md">
                          <User className="w-3 h-3 text-zinc-500" />{u}
                        </span>
                      ))}
                    </div>
                  </Section>
                )}
                {finding.affected_hosts && finding.affected_hosts.length > 0 && (
                  <Section title={`Affected Hosts (${finding.affected_hosts.length})`}>
                    <div className="flex flex-wrap gap-1.5">
                      {finding.affected_hosts.map(h => (
                        <span key={h} className="flex items-center gap-1 text-xs text-zinc-300 bg-zinc-800 border border-zinc-700 px-2 py-1 rounded-md">
                          <Server className="w-3 h-3 text-zinc-500" />{h}
                        </span>
                      ))}
                    </div>
                  </Section>
                )}
              </div>

              {/* MITRE ATT&CK */}
              {finding.mitre_ids && finding.mitre_ids.length > 0 && (
                <Section title="MITRE ATT&CK Techniques">
                  <div className="flex flex-wrap gap-2">
                    {finding.mitre_ids.map(t => (
                      <a
                        key={t}
                        href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                        className="flex items-center gap-1.5 text-xs text-blue-300 bg-blue-500/10 border border-blue-500/20 px-2.5 py-1 rounded-md hover:bg-blue-500/20 transition-colors"
                      >
                        <Shield className="w-3 h-3" />
                        {t}
                        <ExternalLink className="w-2.5 h-2.5 opacity-70" />
                      </a>
                    ))}
                    {finding.mitre_techniques?.map(t => (
                      <span key={t} className="text-xs text-zinc-400 bg-zinc-800 border border-zinc-700 px-2.5 py-1 rounded-md">{t}</span>
                    ))}
                  </div>
                </Section>
              )}

              {/* ML Anomaly Score */}
              {finding.anomaly_score !== undefined && (
                <Section title="ML Anomaly Score">
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${finding.anomaly_score * 100}%` }}
                        transition={{ duration: 0.6, ease: "easeOut" }}
                        className={cn("h-full rounded-full",
                          finding.anomaly_score >= 0.7 ? "bg-red-500" :
                          finding.anomaly_score >= 0.4 ? "bg-orange-500" : "bg-yellow-500"
                        )}
                      />
                    </div>
                    <span className="text-sm font-bold text-white w-12 text-right">
                      {(finding.anomaly_score * 100).toFixed(0)}%
                    </span>
                    {finding.ml_method && (
                      <span className="text-xs text-zinc-500">({finding.ml_method})</span>
                    )}
                  </div>
                </Section>
              )}

              {/* Finding ID footer */}
              <div className="flex items-center justify-between pt-2 border-t border-zinc-800">
                <span className="text-[10px] text-zinc-600 font-mono">ID: {finding.id}</span>
                <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", sev.badgeBg)}>
                  {finding.detection_type === "rule" ? "✓ Rule Match" : finding.detection_type === "ml_anomaly" ? "⚡ ML Detection" : "🌍 Geo Anomaly"}
                </span>
              </div>

            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
