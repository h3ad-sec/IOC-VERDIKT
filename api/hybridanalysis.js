export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://h3ad-sec.github.io');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-user-key');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = req.headers['x-user-key'];
  if (!apiKey) return res.status(400).json({ error: 'Missing API key. Add your own key in Settings.' });

  const { ip, hash, htype } = req.query;
  const headers = { 'api-key': apiKey, 'User-Agent': 'Falcon Sandbox', 'accept': 'application/json' };

  try {
    if (ip) {
      if (!/^[0-9a-fA-F:.]{2,45}$/.test(ip))
        return res.status(400).json({ error: 'Invalid IP format' });
      const upstream = await fetch('https://www.hybrid-analysis.com/api/v2/search/terms', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `terms[network_ip]=${encodeURIComponent(ip)}`,
      });
      if (!upstream.ok) return res.status(200).json({ count: 0, result: [] });
      return res.status(200).json(await upstream.json());

    } else if (hash && htype) {
      const htypeMap = { md5: 32, sha1: 40, sha256: 64 };
      const expectedLen = htypeMap[htype];
      if (!expectedLen)
        return res.status(400).json({ error: 'htype must be md5, sha1, or sha256' });
      if (!/^[0-9a-fA-F]+$/.test(hash) || hash.length !== expectedLen)
        return res.status(400).json({ error: `Invalid ${htype} hash format` });

      const h = hash.toLowerCase();

      if (htype === 'sha256') {
        /* Direct lookup — same endpoint the HA console uses */
        const upstream = await fetch(
          `https://www.hybrid-analysis.com/api/v2/overview/${h}`,
          { method: 'GET', headers }
        );
        if (!upstream.ok) return res.status(200).json({ count: 0, result: [] });
        const data = await upstream.json();
        const reports = (data.reports?.length) ? data.reports : [];
        /* Attach overview-level fields (sha256, md5, sha1, tags, type) to the response
           so the parser can read them — sub-reports don't carry these fields */
        return res.status(200).json({
          count: reports.length,
          result: reports,
          sha256:              data.sha256              || null,
          md5:                 data.md5                 || null,
          sha1:                data.sha1                || null,
          verdict:             data.verdict             || null,
          threat_score:        data.threat_score        || null,
          vx_family:           data.vx_family           || null,
          malware_family:      data.malware_family      || null,
          classification_tags: data.classification_tags || [],
          type_short:          data.type_short          || [],
          size:                data.size                || null,
        });
      }

      /* MD5 / SHA1 — use GET /search/hash */
      const upstream = await fetch(
        `https://www.hybrid-analysis.com/api/v2/search/hash?hash=${encodeURIComponent(h)}`,
        { method: 'GET', headers }
      );
      if (!upstream.ok) return res.status(200).json({ count: 0, result: [] });
      return res.status(200).json(await upstream.json());

    } else {
      return res.status(400).json({ error: 'Missing parameter: ip, or hash+htype' });
    }
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
