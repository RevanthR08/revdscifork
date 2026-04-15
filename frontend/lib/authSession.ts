export type AuthRole = "admin" | "user"

export type AuthSession = {
  email: string
  name: string
  role: AuthRole
  lastLogin: string
}

const SESSION_KEY = "auth_session"

export const ALLOWED_ACCOUNTS: Array<{ email: string; role: AuthRole; password: string; name: string }> = [
  {
    email: "admin@4sic.local",
    role: "admin",
    password: "Admin@123",
    name: "Security Admin",
  },
  {
    email: "analyst@4sic.local",
    role: "user",
    password: "User@123",
    name: "SOC Analyst",
  },
]

export function getAuthSession(): AuthSession | null {
  if (typeof window === "undefined") return null
  const raw = window.sessionStorage.getItem(SESSION_KEY) || window.localStorage.getItem(SESSION_KEY)
  if (!raw) return null

  try {
    const parsed = JSON.parse(raw) as AuthSession
    if (!parsed?.email || !parsed?.role) return null
    return parsed
  } catch {
    return null
  }
}

export function saveAuthSession(session: AuthSession) {
  if (typeof window === "undefined") return
  // Use sessionStorage so multiple tabs/devices can log in as different roles simultaneously.
  window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(session))
  // Keep localStorage clear to avoid cross-tab role collisions from older versions.
  window.localStorage.removeItem(SESSION_KEY)
}

export function clearAuthSession() {
  if (typeof window === "undefined") return
  window.sessionStorage.removeItem(SESSION_KEY)
  window.localStorage.removeItem(SESSION_KEY)
}

export function authenticateByEmail(email: string, password: string): AuthSession | null {
  const found = ALLOWED_ACCOUNTS.find(
    (account) => account.email.toLowerCase() === email.trim().toLowerCase() && account.password === password
  )

  if (!found) return null

  return {
    email: found.email,
    role: found.role,
    name: found.name,
    lastLogin: new Date().toISOString(),
  }
}
