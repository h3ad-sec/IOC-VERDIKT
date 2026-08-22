export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://h3ad-sec.github.io');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-user-key');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = req.headers['x-user-key'];
  if (!apiKey) return res.status(400).json({ error: 'Missing API key. Add your own key in Settings.' });

  const { q, type } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing q parameter' });

  const headers = {
    'Content-Type': 'application/json',
    'Auth-Key': apiKey,
  };
  /* Only domain/url/ip:port/md5_hash/sha256_hash are documented ioc_type
     values for search_ioc (confirmed against threatfox.abuse.ch/api/),
     sha1_hash/sha512_hash are not in that enum. hash_sha1/hash_sha512
     intentionally have no entry here so the ioc_type filter is omitted
     for them (falls back to an unfiltered search_term-only query, same
     as abuse.ch's own reference script) rather than risk filtering out
     every real match with an unrecognized enum value. */
  const tfIocTypeMap = {
    ip: 'ip:port', ipv6: 'ip:port',
    domain: 'domain', url: 'url',
    hash_md5: 'md5_hash', hash_sha256: 'sha256_hash',
  };

  /* Auth failures come back as HTTP 401 (missing key) or 403 with
     query_status:'unknown_auth_key' (invalid key), not as a normal
     no_result response, they must not be coerced into EMPTY or every
     query with a bad/expired key silently looks like "not found". */
  async function tfPost(body) {
    const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => null);
    return { status: r.status, data };
  }

  try {
    const isHashMd5    = type === 'hash_md5'    || (!type && /^[0-9a-fA-F]{32}$/.test(q));
    const isHashSha256 = type === 'hash_sha256' || (!type && /^[0-9a-fA-F]{64}$/.test(q));

    let result;
    if (isHashMd5 || isHashSha256) {
      result = await tfPost({ query: 'search_hash', hash: q.toLowerCase() });
      if (!result.data || result.data.query_status === 'illegal_query')
        result = await tfPost({ query: 'search_ioc', search_term: q.toLowerCase() });
    } else {
      const body = { query: 'search_ioc', search_term: q };
      const tfType = tfIocTypeMap[type];
      if (tfType) body.ioc_type = tfType;
      result = await tfPost(body);
    }

    if (result.data?.query_status === 'unknown_auth_key')
      return res.status(401).json({ error: 'Invalid ThreatFox API key' });
    if (!result.data)
      return res.status(result.status >= 400 ? result.status : 502).json({ error: 'Upstream request failed' });

    return res.status(result.status).json(result.data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
