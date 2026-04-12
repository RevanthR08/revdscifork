// This file is intentionally left minimal.
// In mock mode, all data is served from lib/mockData.ts
// No backend proxy is needed.
import type { NextApiRequest, NextApiResponse } from 'next'

export default function handler(_req: NextApiRequest, res: NextApiResponse) {
  res.status(404).json({ error: 'API proxy disabled in mock mode. Data is served from static mock datasets.' })
}
