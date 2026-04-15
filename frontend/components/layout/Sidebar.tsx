import React, { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/router"
import { motion, AnimatePresence } from "framer-motion"
import {
 
  Upload,
  BarChart3,
  AlertTriangle,
  GitBranch,
  FileText,
  MessageSquare,
  Home,
  Settings,
  ChevronLeft,
  ChevronRight,
  X,
  Activity,
  Lock,
  Eye,
} from "lucide-react"
import ThemeToggle from "./ThemeToggle"
import { cn } from "@/lib/utils"
import { LogOut } from "lucide-react"
import { clearAuthSession, getAuthSession } from "@/lib/authSession"

interface SidebarProps {
  analysisId?: string
  collapsed: boolean
  onToggle: () => void
  mobileOpen?: boolean
  onMobileClose?: () => void
}

const sidebarVariants = {
  expanded: { width: 260 },
  collapsed: { width: 72 },
}

const itemVariants = {
  hidden: { opacity: 0, x: -10 },
  visible: { opacity: 1, x: 0 },
}

export default function Sidebar({ analysisId, collapsed, onToggle, mobileOpen = false, onMobileClose }: SidebarProps) {
  const router = useRouter()
  const [role, setRole] = useState<"admin" | "user">("user")

  React.useEffect(() => {
    const session = getAuthSession()
    setRole(session?.role === "admin" ? "admin" : "user")
  }, [])

  const mainNavItems = [
    { href: "/dashboard", label: "Dashboard", icon: Home },
    { href: "/chat", label: "Secure Chat", icon: MessageSquare },
    ...(role === "admin" ? [{ href: "/chat-admin", label: "Chat Admin", icon: Settings }] : []),
  ]

  const analysisNavItems = analysisId
    ? [
        { href: `/analysis/${analysisId}`, label: "Overview", icon: BarChart3 },
        { href: `/analysis/${analysisId}/findings`, label: "Findings", icon: AlertTriangle },
        { href: `/analysis/${analysisId}/chains`, label: "Attack Chains", icon: GitBranch },
        { href: `/analysis/${analysisId}/summary`, label: "AI Summary", icon: FileText },
      ]
    : []

  const isActive = (href: string) => router.pathname === href

  return (
    <motion.aside
      initial={false}
      animate={collapsed ? "collapsed" : "expanded"}
      variants={sidebarVariants}
      transition={{ duration: 0.2, ease: "easeInOut" }}
      className={cn(
        "fixed left-0 top-0 h-screen bg-zinc-950 border-r border-zinc-800 z-50 flex flex-col",
        "transition-transform duration-200",
        mobileOpen ? "translate-x-0" : "-translate-x-full",
        "lg:translate-x-0"
      )}
    >
      {/* Header */}
      <div className="h-16 flex items-center px-4 border-b border-zinc-800">
        <div className="flex items-center gap-3 w-full justify-between">
          <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-transparent flex items-center justify-center rounded-md overflow-hidden">
            <img src="/logo.png" alt="4SIC" className="w-6 h-6 object-cover" />
          </div>
          <AnimatePresence>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: "auto" }}
                exit={{ opacity: 0, width: 0 }}
                className="overflow-hidden whitespace-nowrap"
              >
                <span className="font-montserrat font-extrabold text-white text-base leading-none">4SIC</span>
              </motion.div>
            )}
          </AnimatePresence>
          </div>
          <button
            onClick={onMobileClose}
            className="inline-flex lg:hidden items-center justify-center w-8 h-8 rounded-md border border-zinc-700 text-zinc-300"
            aria-label="Close navigation menu"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 overflow-y-auto">
        {/* Main Section */}
        <div className="mb-6">
          {!collapsed && (
            <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider px-3 mb-2 block">
              Main
            </span>
          )}
          <ul className="space-y-1">
            {mainNavItems.map((item) => (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className={cn(
                    "flex items-center gap-3 px-3 py-2.5 text-sm transition-all duration-150 group",
                    isActive(item.href)
                      ? "text-white"
                      : "text-zinc-400"
                  )}
                  style={{
                    borderRadius: "6px",
                    backgroundColor: isActive(item.href) ? "#3b3486" : undefined,
                    color: isActive(item.href) ? "#ffffff" : undefined,
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive(item.href)) {
                      e.currentTarget.style.backgroundColor = "#3b3486"
                      e.currentTarget.style.color = "#ffffff"
                      e.currentTarget.querySelectorAll("span, svg").forEach(el => {
                        (el as HTMLElement).style.color = "#ffffff"
                      })
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive(item.href)) {
                      e.currentTarget.style.backgroundColor = ""
                      e.currentTarget.style.color = ""
                      e.currentTarget.querySelectorAll("span, svg").forEach(el => {
                        (el as HTMLElement).style.color = ""
                      })
                    }
                  }}
                  onClick={() => onMobileClose?.()}
                >
                  <item.icon className="w-5 h-5 flex-shrink-0" />
                  <AnimatePresence>
                    {!collapsed && (
                      <motion.span
                        variants={itemVariants}
                        initial="hidden"
                        animate="visible"
                        exit="hidden"
                        className="whitespace-nowrap"
                      >
                        {item.label}
                      </motion.span>
                    )}
                  </AnimatePresence>
                </Link>
              </li>
            ))}
          </ul>
        </div>

        {/* Analysis Section */}
        {analysisNavItems.length > 0 && (
          <div className="mb-6">
            {!collapsed && (
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider px-3 mb-2 block">
                Analysis
              </span>
            )}
            <ul className="space-y-1">
              {analysisNavItems.map((item) => (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2.5 text-sm transition-all duration-150",
                      isActive(item.href)
                        ? "text-white"
                        : "text-zinc-400"
                    )}
                    style={{
                      borderRadius: "6px",
                      backgroundColor: isActive(item.href) ? "#3b3486" : undefined,
                      color: isActive(item.href) ? "#ffffff" : undefined,
                    }}
                    onMouseEnter={(e) => {
                      if (!isActive(item.href)) {
                        e.currentTarget.style.backgroundColor = "#3b3486"
                        e.currentTarget.style.color = "#ffffff"
                        e.currentTarget.querySelectorAll("span, svg").forEach(el => {
                          (el as HTMLElement).style.color = "#ffffff"
                        })
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive(item.href)) {
                        e.currentTarget.style.backgroundColor = ""
                        e.currentTarget.style.color = ""
                        e.currentTarget.querySelectorAll("span, svg").forEach(el => {
                          (el as HTMLElement).style.color = ""
                        })
                      }
                    }}
                    onClick={() => onMobileClose?.()}
                  >
                    <item.icon className="w-5 h-5 flex-shrink-0" />
                    <AnimatePresence>
                      {!collapsed && (
                        <motion.span
                          variants={itemVariants}
                          initial="hidden"
                          animate="visible"
                          exit="hidden"
                          className="whitespace-nowrap"
                        >
                          {item.label}
                        </motion.span>
                      )}
                    </AnimatePresence>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}

      </nav>

      {/* Footer */}
      <div className="p-3 border-t border-zinc-800 space-y-2">
        <div className="flex items-center justify-center">
          <ThemeToggle />
        </div>
        <button
          onClick={() => {
            clearAuthSession();
            router.push('/auth');
            onMobileClose?.();
          }}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors duration-150"
        >
          <LogOut className="w-4 h-4" />
          {!collapsed && <span className="text-sm">Logout</span>}
        </button>

        <button
          onClick={onToggle}
          className="hidden lg:flex w-full items-center justify-center gap-2 px-3 py-2 rounded-md text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors duration-150"
        >
          {collapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <>
              <ChevronLeft className="w-4 h-4" />
              <span className="text-sm">Collapse</span>
            </>
          )}
        </button>
      </div>
    </motion.aside>
  )
}
