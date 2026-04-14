// v1.0.1 - Fixed duplicate imports
import React, { useState, useEffect } from "react"
import { useRouter } from "next/router"
import { motion } from "framer-motion"
import Sidebar from "./Sidebar"

interface DashboardLayoutProps {
  children: React.ReactNode
  analysisId?: string
}


export default function DashboardLayout({ children, analysisId }: DashboardLayoutProps) {
  const router = useRouter()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [isAuthorized, setIsAuthorized] = useState(false)

  useEffect(() => {
    // Immediate check on mount
    const session = localStorage.getItem('auth_session')
    if (!session) {
      router.push('/auth')
    } else {
      setIsAuthorized(true)
    }
  }, [router])

  // Don't render anything while checking or if unauthorized
  if (!isAuthorized) {
    return <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
      <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
    </div>
  }

  return (
    <div className="min-h-screen bg-zinc-950">
      <Sidebar
        analysisId={analysisId}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />

      <motion.main
        initial={false}
        animate={{
          marginLeft: sidebarCollapsed ? 72 : 260,
        }}
        transition={{ duration: 0.2, ease: "easeInOut" }}
        className="min-h-screen"
      >
        <div className="p-6">
          {children}
        </div>
      </motion.main>
    </div>
  )
}
