import React from "react"
import Head from "next/head"
import Link from "next/link"
import { motion } from "framer-motion"
import { ShieldCheck, Radar, Sparkles, ArrowRight, Upload, FileSearch, BarChart3, Clock3 } from "lucide-react"

const highlights = [
  {
    icon: Upload,
    title: "Ingest Security Logs",
    description: "Upload Windows event data and normalize telemetry in seconds.",
  },
  {
    icon: FileSearch,
    title: "AI Threat Correlation",
    description: "Auto-link suspicious events into coherent attack narratives.",
  },
  {
    icon: ShieldCheck,
    title: "Actionable Triage",
    description: "Prioritized findings with severity, context, and response hints.",
  },
]

const metrics = [
  { label: "Log Events Processed", value: "100K+" },
  { label: "MITRE Techniques Mapped", value: "150+" },
  { label: "Avg Investigation Time Saved", value: "42%" },
  { label: "Analyst Workflow", value: "Ingest to Report" },
]

const workflow = [
  {
    icon: Upload,
    title: "Upload and Normalize",
    description: "Bring raw logs into one structured timeline in a few clicks.",
  },
  {
    icon: FileSearch,
    title: "Correlate and Prioritize",
    description: "Automatically group findings by risk, technique, and attack sequence.",
  },
  {
    icon: BarChart3,
    title: "Visualize and Report",
    description: "Open dashboards, chains, and summaries ready for analyst and leadership review.",
  },
]

export default function HomePage() {
  return (
    <>
      <Head>
        <title>4SIC | Home</title>
        <meta
          name="description"
          content="4SIC is an AI-powered SOC analysis platform for forensic timelines, findings, and attack chain visualization."
        />
      </Head>

      <main className="relative min-h-screen overflow-hidden bg-background">
        <div className="pointer-events-none absolute inset-0 -z-10 opacity-70">
          <div className="absolute -top-24 right-[-120px] h-[520px] w-[520px] rounded-full bg-[radial-gradient(circle,rgba(59,52,134,0.30)_0%,rgba(59,52,134,0.04)_52%,rgba(59,52,134,0)_78%)]" />
          <div className="absolute bottom-[-220px] left-[-120px] h-[500px] w-[500px] rounded-full bg-[radial-gradient(circle,rgba(0,168,204,0.20)_0%,rgba(0,168,204,0.02)_55%,rgba(0,168,204,0)_80%)]" />
        </div>

        <section className="mx-auto flex w-full max-w-none flex-col px-3 pb-12 pt-8 sm:px-4 md:px-6 lg:px-8">
          <motion.header
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45 }}
            className="mb-12 flex items-center justify-between"
          >
            <Link href="/" className="flex items-center gap-3">
              <img src="/logo.png" alt="4SIC" className="h-10 w-10 rounded-md object-cover" />
              <span className="font-montserrat text-3xl font-extrabold tracking-tight leading-none">4SIC</span>
            </Link>

            <div className="flex items-center gap-3">
              <Link
                href="/auth"
                className="rounded-md border border-zinc-700 px-4 py-2 text-sm font-semibold text-zinc-300 transition hover:border-zinc-500 hover:text-white"
              >
                Sign In
              </Link>
              <Link
                href="/dashboard"
                className="rounded-md bg-[#3b3486] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[#4a439b]"
              >
                Open Dashboard
              </Link>
            </div>
          </motion.header>

          <div className="grid gap-10 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="space-y-7"
            >
              <div className="inline-flex items-center gap-2 rounded-full border border-zinc-700/70 bg-zinc-900/70 px-3 py-1 text-xs font-semibold text-zinc-300">
                <Radar className="h-3.5 w-3.5 text-cyan-400" />
                SOC AI Workspace
              </div>

              <h1 className="font-montserrat text-4xl font-extrabold leading-tight text-foreground sm:text-5xl lg:text-6xl">
                Analyze Threats Faster With
                <span className="ml-2 text-[#6C5DD3]">4SIC</span>
              </h1>

              <p className="max-w-2xl text-sm leading-relaxed text-zinc-400 sm:text-base">
                Turn raw Windows logs into clear forensic intelligence. 4SIC combines AI summaries,
                findings triage, and attack-chain visualization so analysts can move from ingestion to
                response with less noise and more confidence.
              </p>

              <div className="flex flex-wrap items-center gap-3">
                <Link
                  href="/auth"
                  className="inline-flex items-center gap-2 rounded-md bg-[#3b3486] px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-[#4a439b]"
                >
                  Start Investigation
                  <ArrowRight className="h-4 w-4" />
                </Link>
                <Link
                  href="/dashboard"
                  className="inline-flex items-center gap-2 rounded-md border border-zinc-700 bg-zinc-900/60 px-5 py-2.5 text-sm font-semibold text-zinc-200 transition hover:border-zinc-500 hover:text-white"
                >
                  Browse Datasets
                </Link>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="rounded-2xl border border-zinc-800/80 bg-zinc-900/60 p-5 shadow-2xl shadow-black/30 backdrop-blur"
            >
              <div className="mb-4 flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Live Stack</p>
                <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                  <Sparkles className="h-3 w-3" />
                  Active
                </span>
              </div>

              <div className="space-y-3">
                {highlights.map((item, idx) => (
                  <motion.div
                    key={item.title}
                    initial={{ opacity: 0, x: 10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.25 + idx * 0.1, duration: 0.35 }}
                    className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-4"
                  >
                    <div className="mb-2 flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-md bg-[#3b3486]/30">
                        <item.icon className="h-4.5 w-4.5 text-[#b9b2ff]" />
                      </div>
                      <h3 className="text-sm font-semibold text-zinc-100">{item.title}</h3>
                    </div>
                    <p className="text-xs leading-relaxed text-zinc-400">{item.description}</p>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
          >
            {metrics.map((item) => (
              <div key={item.label} className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
                <p className="text-xs uppercase tracking-wider text-zinc-500">{item.label}</p>
                <p className="mt-2 text-xl font-bold text-zinc-100">{item.value}</p>
              </div>
            ))}
          </motion.div>

          <motion.section
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.35 }}
            className="mt-12 rounded-2xl border border-zinc-800 bg-zinc-900/50 p-6 sm:p-8"
          >
            <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-wider text-zinc-500">How It Works</p>
                <h2 className="mt-1 font-montserrat text-2xl font-bold text-zinc-100">From Raw Logs to Clear Decisions</h2>
              </div>
              <span className="inline-flex items-center gap-2 rounded-full border border-zinc-700 bg-zinc-950/70 px-3 py-1 text-xs text-zinc-300">
                <Clock3 className="h-3.5 w-3.5 text-cyan-400" />
                Built for fast triage
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {workflow.map((item, idx) => (
                <motion.div
                  key={item.title}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: 0.4 + idx * 0.08 }}
                  className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-4"
                >
                  <div className="mb-3 flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-[#3b3486]/30">
                      <item.icon className="h-4 w-4 text-[#b9b2ff]" />
                    </div>
                    <h3 className="text-sm font-semibold text-zinc-100">{item.title}</h3>
                  </div>
                  <p className="text-xs leading-relaxed text-zinc-400">{item.description}</p>
                </motion.div>
              ))}
            </div>
          </motion.section>
        </section>
      </main>
    </>
  )
}
