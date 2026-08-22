export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://h3ad-sec.github.io');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-user-key');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = req.headers['x-user-key'];
  if (!apiKey) return res.status(400).json({ error: 'Missing API key. Add your own key in Settings.' });

  const { hash } = req.query;
  if (!hash) return res.status(400).json({ error: 'Missing hash parameter' });
  if (!/^[0-9a-fA-F]{32,128}$/.test(hash))
    return res.status(400).json({ error: 'Invalid hash format' });

  // FileScan.io auth header: X-Api-Key (confirmed against the live OpenAPI
  // spec at filescan.io/openapi.json, securitySchemes.apiKey).
  const headers = { 'accept': 'application/json', 'X-Api-Key': apiKey };

  /* /api/reports/search has dedicated md5/sha1/sha256 filter params (per
     the OpenAPI spec) that are the correct way to search by hash, the
     generic `query` param does not reliably match on hash value, use the
     typed param instead. */
  const hashParam = hash.length === 32 ? 'md5' : hash.length === 40 ? 'sha1' : hash.length === 128 ? 'sha512' : 'sha256';

  try {
    const upstream = await fetch(
      `https://www.filescan.io/api/reports/search?${hashParam}=${encodeURIComponent(hash.toLowerCase())}`,
      { method: 'GET', headers }
    );
    const data = await upstream.json().catch(() => null);
    /* Don't coerce auth/rate-limit/upstream failures into a fake empty
       result, that makes every query with a missing/invalid key silently
       look like "not found" instead of surfacing the real problem. */
    if (!upstream.ok || !data) return res.status(upstream.status || 502).json(data ?? { error: 'Upstream request failed' });
    return res.status(200).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
