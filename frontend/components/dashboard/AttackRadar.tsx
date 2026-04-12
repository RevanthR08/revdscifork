import React from "react"
import { motion } from "framer-motion"
import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
} from "recharts"

// MITRE technique ID prefix → tactic
const MITRE_TACTIC_MAP: Record<string, string> = {
  "T1059": "Execution",
  "T1204": "Execution",
  "T1047": "Execution",
  "T1053": "Persistence",
  "T1543": "Persistence",
  "T1547": "Persistence",
  "T1003": "Cred Access",
  "T1550": "Cred Access",
  "T1558": "Cred Access",
  "T1548": "Priv Esc",
  "T1078": "Priv Esc",
  "T1021": "Lateral Mvmt",
  "T1087": "Discovery",
  "T1016": "Discovery",
  "T1057": "Discovery",
  "T1083": "Discovery",
  "T1082": "Discovery",
  "T1562": "Def Evasion",
  "T1218": "Def Evasion",
  "T1027": "Def Evasion",
  "T1486": "Impact",
  "T1490": "Impact",
  "T1566": "Init Access",
  "T1048": "Exfiltration",
  "T1071": "C2",
  "T1134": "Priv Esc",
}

const TACTIC_ORDER = [
  "Init Access",
  "Execution",
  "Persistence",
  "Priv Esc",
  "Def Evasion",
  "Cred Access",
  "Discovery",
  "Lateral Mvmt",
  "C2",
  "Exfiltration",
  "Impact",
]

const CustomRadarTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    return (
      <div
        className="bg-zinc-800 border border-zinc-700 px-3 py-2 text-xs"
        style={{ borderRadius: "6px" }}
      >
        <p className="text-zinc-300 font-semibold mb-1">{payload[0]?.payload?.subject}</p>
        <p className="text-blue-400">Findings: <span className="text-white font-bold">{payload[0]?.value ?? 0}</span></p>
      </div>
    )
  }
  return null
}

interface AttackRadarProps {
  findings: { detection_type: string; severity: string; mitre_techniques?: string[]; mitre_ids?: string[] }[]
}

export default function AttackRadar({ findings }: AttackRadarProps) {
  // Count findings per MITRE tactic
  const tacticCounts: Record<string, number> = {}

  findings.forEach(f => {
    // mitre_ids may come from the summary page findings (mitre_ids) or overview findings (mitre_techniques used as ids)
    const ids: string[] = (f as any).mitre_ids || (f as any).mitre_techniques || []
    ids.forEach(id => {
      // Match by prefix (T1059.001 → T1059)
      const prefix = id.split(".")[0].split("-")[0]
      const tactic = MITRE_TACTIC_MAP[prefix]
      if (tactic) {
        tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1
      }
    })
  })

  // Only include tactics that have findings, but always show at least the top ones
  const activeData = TACTIC_ORDER
    .filter(t => tacticCounts[t] || true) // always show all axes
    .map(t => ({
      subject: t,
      count: tacticCounts[t] || 0,
      fullMark: Math.max(...Object.values(tacticCounts), 5),
    }))

  const maxVal = Math.max(...activeData.map(d => d.count), 1)

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.4 }}
      className="bg-zinc-900 border border-zinc-800 p-4"
      style={{ borderRadius: "6px" }}
    >
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
          MITRE Tactic Coverage
        </p>
        <div className="flex items-center gap-3 text-[10px] text-zinc-500">
          <span className="flex items-center gap-1">
            <span className="inline-block w-2 h-2 rounded-full bg-blue-500" />
            Findings
          </span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <RadarChart data={activeData} margin={{ top: 10, right: 20, bottom: 10, left: 20 }}>
          <defs>
            <radialGradient id="radarGrad" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.4} />
              <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0.1} />
            </radialGradient>
          </defs>
          <PolarGrid stroke="#27272a" />
          <PolarAngleAxis
            dataKey="subject"
            tick={{ fontSize: 9, fill: "#a1a1aa", fontWeight: 600 }}
          />
          <PolarRadiusAxis
            tick={{ fontSize: 8, fill: "#52525b" }}
            domain={[0, maxVal]}
            tickCount={4}
          />
          <Tooltip content={<CustomRadarTooltip />} />
          <Radar
            name="Findings"
            dataKey="count"
            stroke="#3b82f6"
            strokeWidth={2}
            fill="url(#radarGrad)"
            fillOpacity={1}
            dot={{ fill: "#3b82f6", r: 3, strokeWidth: 0 }}
          />
        </RadarChart>
      </ResponsiveContainer>
    </motion.div>
  )
}
