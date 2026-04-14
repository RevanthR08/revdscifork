// v1.0.1 - Fixed duplicate imports
import React, { useState, useEffect } from "react"
import { useRouter } from "next/router"
import { motion } from "framer-motion"
import { Menu } from "lucide-react"
import Sidebar from "./Sidebar"

interface DashboardLayoutProps {
  children: React.ReactNode
  analysisId?: string
}


export default function DashboardLayout({ children, analysisId }: DashboardLayoutProps) {
  const router = useRouter()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [isAuthorized, setIsAuthorized] = useState(false)
  const [isDesktop, setIsDesktop] = useState(false)
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false)

  useEffect(() => {
    // Immediate check on mount
    const session = localStorage.getItem('auth_session')
    if (!session) {
      router.push('/auth')
    } else {
      setIsAuthorized(true)
    }
  }, [router])

  useEffect(() => {
    const updateBreakpoint = () => {
      setIsDesktop(window.innerWidth >= 1024)
    }

    updateBreakpoint()
    window.addEventListener("resize", updateBreakpoint)
    return () => window.removeEventListener("resize", updateBreakpoint)
  }, [])

  // Don't render anything while checking or if unauthorized
  if (!isAuthorized) {
    return <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
      <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
    </div>
  }

  return (
    <div className="min-h-screen bg-zinc-950">
      {!isDesktop && (
        <div className="sticky top-0 z-40 h-14 border-b border-zinc-800 bg-zinc-950/95 backdrop-blur px-4 flex items-center">
          <button
            onClick={() => setMobileSidebarOpen(true)}
            className="inline-flex items-center justify-center w-9 h-9 rounded-md border border-zinc-700 text-zinc-200"
            aria-label="Open navigation menu"
          >
            <Menu className="w-5 h-5" />
          </button>
          <span className="ml-3 font-montserrat font-extrabold text-lg text-white">4SIC</span>
        </div>
      )}

      <Sidebar
        analysisId={analysisId}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileSidebarOpen}
        onMobileClose={() => setMobileSidebarOpen(false)}
      />

      {!isDesktop && mobileSidebarOpen && (
        <button
          className="fixed inset-0 bg-black/45 z-40"
          aria-label="Close navigation menu"
          onClick={() => setMobileSidebarOpen(false)}
        />
      )}

      <motion.main
        initial={false}
        animate={{
          marginLeft: isDesktop ? (sidebarCollapsed ? 72 : 260) : 0,
        }}
        transition={{ duration: 0.2, ease: "easeInOut" }}
        className="min-h-screen"
      >
        <div className="p-4 sm:p-6">
          {children}
        </div>
      </motion.main>
    </div>
  )
}
