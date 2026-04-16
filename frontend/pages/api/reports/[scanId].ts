import type { NextApiRequest, NextApiResponse } from "next"
import { promises as fs } from "fs"
import path from "path"

const REPORT_PATHS_BY_SCAN_ID: Record<string, string> = {
  "ds-003": "dataset3/dataset3_expanded_forensic_report.pdf",
  "ds-004": "dataset4/dataset4_expanded_forensic_report.pdf",
  "ds-005": "dataset5/dataset5_expanded_forensic_report.pdf",
  "ds-006": "dataset6/dataset6_expanded_forensic_report.pdf",
  "ds-007": "dataset7/dataset7_expanded_forensic_report.pdf",
  "ds-008": "dataset8/dataset8_expanded_forensic_report.pdf",
  "ds-009": "dataset9/dataset9_expanded_forensic_report.pdf",
  "ds-010": "dataset10/dataset10_expanded_forensic_report.pdf",

  "user-003": "dataset3/dataset3_expanded_forensic_report.pdf",
  "user-004": "dataset4/dataset4_expanded_forensic_report.pdf",
  "user-005": "dataset5/dataset5_expanded_forensic_report.pdf",
  "user-006": "dataset6/dataset6_expanded_forensic_report.pdf",
  "user-007": "dataset7/dataset7_expanded_forensic_report.pdf",
  "user-008": "dataset8/dataset8_expanded_forensic_report.pdf",
  "user-009": "dataset9/dataset9_expanded_forensic_report.pdf",
  "user-010": "dataset10/dataset10_expanded_forensic_report.pdf",

  // Generic upload flow fallback
  "mock-upload-id": "dataset9/dataset9_expanded_forensic_report.pdf",
}

function normalizeScanId(input: string) {
  const raw = input.trim().toLowerCase()
  if (!raw) return ""

  const userCompact = raw.match(/^user[-_]?(\d{1,4})$/)
  if (userCompact) {
    const n = Number.parseInt(userCompact[1], 10)
    if (!Number.isNaN(n)) {
      return `user-${String(n).padStart(3, "0")}`
    }
  }

  const dsCompact = raw.match(/^ds[-_]?(\d{1,4})$/)
  if (dsCompact) {
    const n = Number.parseInt(dsCompact[1], 10)
    if (!Number.isNaN(n)) {
      return `ds-${String(n).padStart(3, "0")}`
    }
  }

  return raw
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET")
    return res.status(405).json({ error: "Method not allowed" })
  }

  const rawScanId = Array.isArray(req.query.scanId) ? req.query.scanId[0] : req.query.scanId
  const scanId = normalizeScanId(String(rawScanId || ""))
  const mappedPath = REPORT_PATHS_BY_SCAN_ID[scanId]

  if (!mappedPath) {
    return res.status(404).json({ error: `No PDF report mapped for scan ${scanId}` })
  }

  const absolutePath = path.join(process.cwd(), "datasets", mappedPath)

  try {
    const pdfBuffer = await fs.readFile(absolutePath)
    const fileName = path.basename(absolutePath)

    res.setHeader("Content-Type", "application/pdf")
    res.setHeader("Content-Disposition", `attachment; filename=\"${fileName}\"`)
    return res.status(200).send(pdfBuffer)
  } catch {
    return res.status(404).json({ error: `PDF file not found at ${mappedPath}` })
  }
}
