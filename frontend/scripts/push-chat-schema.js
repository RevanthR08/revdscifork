const { Client } = require("pg")
const fs = require("fs")
const path = require("path")

function loadEnvFile(envPath) {
  if (!fs.existsSync(envPath)) return
  const content = fs.readFileSync(envPath, "utf-8")
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) continue
    const equalsIndex = trimmed.indexOf("=")
    if (equalsIndex <= 0) continue
    const key = trimmed.slice(0, equalsIndex).trim()
    const value = trimmed.slice(equalsIndex + 1).trim()
    if (!process.env[key]) {
      process.env[key] = value
    }
  }
}

loadEnvFile(path.resolve(__dirname, "../.env.local"))

const databaseUrl = process.env.SUPABASE_DATABASE_URL
if (!databaseUrl) {
  console.error("Missing SUPABASE_DATABASE_URL in environment. Set it in frontend/.env.local.")
  process.exit(1)
}

const sqlFile = path.resolve(__dirname, "chat-schema.sql")
if (!fs.existsSync(sqlFile)) {
  console.error("Schema file not found: ", sqlFile)
  process.exit(1)
}

const sql = fs.readFileSync(sqlFile, "utf-8")

async function run() {
  const client = new Client({ connectionString: databaseUrl })
  try {
    await client.connect()
    console.log("Connected to Supabase database.")
    console.log("Applying chat schema...")
    await client.query(sql)
    console.log("Chat schema applied successfully.")
  } catch (error) {
    console.error("Schema deployment failed:", error)
    process.exit(1)
  } finally {
    await client.end()
  }
}

run()
