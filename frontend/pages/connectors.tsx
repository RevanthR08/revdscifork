import React, { useMemo, useState } from "react"
import Link from "next/link"
import DashboardLayout from "@/components/layout/DashboardLayout"
import { AnimatePresence, motion } from "framer-motion"
import { Link2, ShieldCheck, CheckCircle2, AlertTriangle, RefreshCw, KeyRound, FileText, ArrowLeft } from "lucide-react"
import { cn } from "@/lib/utils"

type Connector = {
  code: string
  brand: "splunk" | "suricata" | "webhook" | "custom"
  name: string
  type: string
  status: "Active" | "Disconnected"
  lastSync: string
  seal: string
}

const initialConnectors: Connector[] = [
  {
    code: "SP",
    brand: "splunk",
    name: "Splunk SIEM",
    type: "Security Information & Event Management",
    status: "Active",
    lastSync: "Syncing Now",
    seal: "SHA-256 Verified",
  },
  {
    code: "SU",
    brand: "suricata",
    name: "Suricata IDS",
    type: "Intrusion Detection System",
    status: "Active",
    lastSync: "5 mins ago",
    seal: "SHA-256 Verified",
  },
  {
    code: "WH",
    brand: "webhook",
    name: "Generic Webhook",
    type: "Custom HTTP POST Endpoint",
    status: "Active",
    lastSync: "10 mins ago",
    seal: "SHA-256 Verified",
  },
]

const nowLabel = () => "Syncing Now"

const makeKey = () => {
  const chars = "abcdef0123456789"
  let raw = ""
  for (let i = 0; i < 32; i++) raw += chars[Math.floor(Math.random() * chars.length)]
  return raw
}

const maskKey = (key: string) => `${key.slice(0, 4)}${"*".repeat(20)}${key.slice(-4)}`

function ConnectorLogo({ connector }: { connector: Connector }) {
  const base = "w-9 h-9 rounded-md flex items-center justify-center text-[11px] font-black border"

  if (connector.brand === "splunk") {
    return <div className={`${base} bg-orange-500/15 border-orange-500/40 text-orange-300`}>SP</div>
  }
  if (connector.brand === "suricata") {
    return <div className={`${base} bg-red-500/15 border-red-500/40 text-red-300`}>SU</div>
  }
  if (connector.brand === "webhook") {
    return <div className={`${base} bg-blue-500/15 border-blue-500/40 text-blue-300`}>WH</div>
  }
  return <div className={`${base} bg-violet-500/15 border-violet-500/40 text-violet-300`}>{connector.code}</div>
}

export default function ConnectorsPage() {
  const [connectors, setConnectors] = useState<Connector[]>(initialConnectors)
  const [selectedConnector, setSelectedConnector] = useState<string | null>(null)
  const [selectedConfigCode, setSelectedConfigCode] = useState<string>("WH")
  const [apiKey, setApiKey] = useState(makeKey())
  const [shaEnabled, setShaEnabled] = useState(true)
  const [testingWebhook, setTestingWebhook] = useState(false)
  const [showSecurityDetails, setShowSecurityDetails] = useState(false)
  const [banner, setBanner] = useState<string>("")

  const activeCount = useMemo(() => connectors.filter((c) => c.status === "Active").length, [connectors])

  const latestSignature = useMemo(() => {
    const signature = makeKey()
    return `Verified ${signature.slice(0, 4)}...${signature.slice(-4)}`
  }, [connectors])

  const mockLogsCount = 1200 + connectors.length * 8
  const mockAlerts = 50000 + activeCount * 125

  const logs = useMemo(() => {
    if (!selectedConnector) return []
    return [
      `[${new Date().toLocaleTimeString()}] Connector ${selectedConnector}: Heartbeat accepted`,
      `[${new Date().toLocaleTimeString()}] SHA-256 digest chain verified`,
      `[${new Date().toLocaleTimeString()}] Alert payload queued for enrichment`,
    ]
  }, [selectedConnector, connectors])

  const handleConnectorAction = (code: string) => {
    setConnectors((prev) =>
      prev.map((c) => {
        if (c.code !== code) return c
        if (c.status === "Disconnected") {
          setBanner(`${c.name} connected.`)
          setSelectedConfigCode(code)
          return { ...c, status: "Active", lastSync: nowLabel(), seal: "SHA-256 Verified" }
        }
        setSelectedConfigCode(code)
        setBanner(`Opened ${c.name} configuration.`)
        return { ...c, lastSync: nowLabel() }
      })
    )
  }

  const selectedConfig = connectors.find((c) => c.code === selectedConfigCode) || connectors[0]

  const addMockConnector = () => {
    const code = `N${Math.floor(Math.random() * 90 + 10)}`
    setConnectors((prev) => [
      ...prev,
      {
        code,
        brand: "custom",
        name: `New Connector ${code}`,
        type: "Custom SIEM Ingestion Endpoint",
        status: "Disconnected",
        lastSync: "Never",
        seal: "Verification Failed",
      },
    ])
    setBanner("Added a new mock connector.")
  }

  const regenerateKey = () => {
    setApiKey(makeKey())
    setBanner("Webhook API key regenerated.")
  }

  const testWebhook = () => {
    setTestingWebhook(true)
    setBanner("Testing webhook endpoint...")
    setTimeout(() => {
      setTestingWebhook(false)
      setBanner("Webhook test successful. Payload signature validated.")
    }, 900)
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-300 hover:text-white hover:border-zinc-500"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back
          </Link>
        </motion.div>

        <AnimatePresence>
          {banner && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="rounded-md border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-xs text-blue-200"
            >
              {banner}
            </motion.div>
          )}
        </AnimatePresence>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="bg-zinc-900 border border-zinc-800 rounded-md p-5"
        >
          <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-zinc-500">Connector Pipeline v4.2</p>
              <h1 className="mt-1 text-2xl font-bold text-white">Integrations & Connectors</h1>
              <p className="mt-2 text-sm text-zinc-400 max-w-3xl">
                Configure real-time SIEM/IDS webhooks and manage cryptographic chain of custody for all evidence.
                Tamper-proof audit trail guaranteed.
              </p>
            </div>
            <button
              onClick={addMockConnector}
              className="inline-flex items-center justify-center rounded-md bg-[#3b3486] px-4 py-2 text-sm font-semibold text-white hover:bg-[#4a439b]"
            >
              ADD NEW CONNECTOR
            </button>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {[
            { label: "Active Connectors", value: String(activeCount) },
            { label: "Latest Signature", value: latestSignature },
            { label: "Audit Logs", value: mockLogsCount.toLocaleString() },
            { label: "Processed Alerts", value: mockAlerts.toLocaleString() },
          ].map((card, idx) => (
            <motion.div
              key={card.label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.08 * idx }}
              className="bg-zinc-900 border border-zinc-800 rounded-md p-4"
            >
              <p className="text-xs uppercase tracking-wider text-zinc-500">{card.label}</p>
              <p className="mt-2 text-lg font-bold text-white">{card.value}</p>
            </motion.div>
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="bg-zinc-900 border border-zinc-800 rounded-md overflow-hidden"
        >
          <div className="px-5 py-4 border-b border-zinc-800">
            <h2 className="text-sm font-bold text-white">Active Connector Pipeline</h2>
          </div>
          <div className="overflow-x-auto scrollbar-transparent">
            <table className="w-full min-w-[900px]">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="text-left text-[10px] font-bold text-zinc-500 uppercase px-4 py-3">Source</th>
                  <th className="text-left text-[10px] font-bold text-zinc-500 uppercase px-4 py-3">Status</th>
                  <th className="text-left text-[10px] font-bold text-zinc-500 uppercase px-4 py-3">Last Sync</th>
                  <th className="text-left text-[10px] font-bold text-zinc-500 uppercase px-4 py-3">Security Seal</th>
                  <th className="text-left text-[10px] font-bold text-zinc-500 uppercase px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {connectors.map((connector, idx) => (
                  <motion.tr
                    key={connector.code}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.03 * idx }}
                    className="border-b border-zinc-800/50 hover:bg-zinc-800/20"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-start gap-3">
                        <ConnectorLogo connector={connector} />
                        <div>
                          <p className="text-sm font-semibold text-white">{connector.name}</p>
                          <p className="text-xs text-zinc-500">{connector.type}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          "inline-flex items-center rounded px-2 py-1 text-[10px] font-bold uppercase",
                          connector.status === "Active" ? "bg-emerald-500/15 text-emerald-300" : "bg-red-500/15 text-red-300"
                        )}
                      >
                        {connector.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-300">{connector.lastSync}</td>
                    <td className="px-4 py-3 text-xs">
                      <span className={cn("font-semibold", connector.seal === "Verification Failed" ? "text-red-300" : "text-blue-300")}>
                        {connector.seal}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleConnectorAction(connector.code)}
                          className="rounded-md px-2.5 py-1 text-[11px] font-semibold bg-zinc-800 text-zinc-200 hover:bg-zinc-700 transition-colors"
                        >
                          {connector.status === "Disconnected" ? "Connect" : "Configure"}
                        </button>
                        <button
                          onClick={() => {
                            setSelectedConnector(connector.code)
                            setBanner(`Viewing ${connector.name} logs.`)
                          }}
                          className="rounded-md px-2.5 py-1 text-[11px] font-semibold bg-zinc-800 text-zinc-200 hover:bg-zinc-700 transition-colors"
                        >
                          View Logs
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        <AnimatePresence>
          {selectedConnector && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="bg-zinc-900 border border-zinc-800 rounded-md p-4"
          >
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-white">Connector Logs ({selectedConnector})</h3>
              <button
                onClick={() => setSelectedConnector(null)}
                className="text-xs rounded-md bg-zinc-800 px-2 py-1 text-zinc-300 hover:bg-zinc-700"
              >
                Close
              </button>
            </div>
            <div className="space-y-2">
              {logs.map((line, idx) => (
                <p key={idx} className="text-xs font-mono text-zinc-300 bg-zinc-950 border border-zinc-800 rounded px-3 py-2">
                  {line}
                </p>
              ))}
            </div>
          </motion.div>
        )}
        </AnimatePresence>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-zinc-900 border border-zinc-800 rounded-md p-5 space-y-4"
        >
          <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Tool Configuration - Tamper-Proof Webhook</h3>
              <p className="text-xs text-zinc-500 mt-1">
                {selectedConfig.name} - {selectedConfig.type}
              </p>
            </div>
            <span
              className={cn(
                "inline-flex w-fit items-center gap-1 rounded px-2 py-1 text-[10px] font-bold uppercase",
                shaEnabled ? "bg-emerald-500/15 text-emerald-300" : "bg-yellow-500/20 text-yellow-300"
              )}
            >
              {shaEnabled ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
              {shaEnabled ? "Operational" : "Limited"}
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-zinc-400 uppercase">Webhook Endpoint URL</label>
              <div className="mt-1 rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200">
                https://api.yoursoc.com/webhook/{selectedConfig.code.toLowerCase()}-channel
              </div>
            </div>
            <div>
              <label className="text-xs font-semibold text-zinc-400 uppercase">API Key</label>
              <div className="mt-1 rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200">
                {maskKey(apiKey)}
              </div>
            </div>
          </div>

          <div className="rounded-md border border-zinc-700 bg-zinc-950 p-4 space-y-3">
            <button
              onClick={() => {
                setShaEnabled((prev) => !prev)
                setBanner(`SHA-256 chain of custody ${shaEnabled ? "disabled" : "enabled"}.`)
              }}
              className="w-full text-left flex items-start gap-2"
            >
              <ShieldCheck className="w-4 h-4 text-blue-300 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-white">ENABLE SHA-256 CHAIN OF CUSTODY</p>
                <p className="text-xs text-zinc-500">Cryptographic integrity for all ingested evidence payloads</p>
              </div>
            </button>
            <div className="flex items-start gap-2">
              <FileText className="w-4 h-4 text-emerald-300 mt-0.5" />
              <div>
                <p className={cn("text-sm font-semibold", shaEnabled ? "text-emerald-300" : "text-yellow-300")}>
                  {shaEnabled ? "Cryptographic Integrity Maintained" : "Cryptographic Integrity Paused"}
                </p>
                <p className="text-xs text-zinc-400">Listening for POST requests in standard JSON format.</p>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={regenerateKey}
              className="inline-flex items-center gap-1 rounded-md bg-zinc-800 px-3 py-2 text-xs font-semibold text-zinc-200 hover:bg-zinc-700"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Regenerate API Key
            </button>
            <button
              onClick={() => {
                setShowSecurityDetails((prev) => !prev)
                setBanner("Security details toggled.")
              }}
              className="inline-flex items-center gap-1 rounded-md bg-zinc-800 px-3 py-2 text-xs font-semibold text-zinc-200 hover:bg-zinc-700"
            >
              <KeyRound className="w-3.5 h-3.5" />
              Security Details
            </button>
            <button
              onClick={testWebhook}
              disabled={testingWebhook}
              className="inline-flex items-center gap-1 rounded-md bg-zinc-800 px-3 py-2 text-xs font-semibold text-zinc-200 hover:bg-zinc-700 disabled:opacity-60 disabled:cursor-not-allowed"
            >
              <Link2 className="w-3.5 h-3.5" />
              {testingWebhook ? "Testing..." : "Test Webhook"}
            </button>
          </div>

          {showSecurityDetails && (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-md border border-zinc-700 bg-zinc-950 p-4 space-y-2"
            >
              <p className="text-xs uppercase tracking-wider text-zinc-500">Security Details</p>
              <p className="text-sm text-zinc-200">Connector: {selectedConfig.name}</p>
              <p className="text-xs text-zinc-400">Signature: SHA-256:{apiKey.slice(0, 8)}...{apiKey.slice(-8)}</p>
              <p className="text-xs text-zinc-400">Chain of custody: {shaEnabled ? "Enabled" : "Disabled"}</p>
            </motion.div>
          )}
        </motion.div>
      </div>
    </DashboardLayout>
  )
}
