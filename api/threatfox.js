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
  const EMPTY = { query_status: 'no_result', data: [] };

  const tfIocTypeMap = {
    ip: 'ip:port', ipv6: 'ip:port',
    domain: 'domain', url: 'url',
    hash_md5: 'md5_hash', hash_sha256: 'sha256_hash',
    hash_sha1: 'sha1_hash', hash_sha512: 'sha512_hash',
  };

  async function tfPost(body) {
    const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    if (r.status === 401) return null;
    if (!r.ok) return null;
    return r.json();
  }

  try {
    const isHashMd5    = type === 'hash_md5'    || (!type && /^[0-9a-fA-F]{32}$/.test(q));
    const isHashSha256 = type === 'hash_sha256' || (!type && /^[0-9a-fA-F]{64}$/.test(q));

    let data = null;
    if (isHashMd5 || isHashSha256) {
      data = await tfPost({ query: 'search_hash', hash: q.toLowerCase() });
      if (!data || data.query_status === 'illegal_query')
        data = await tfPost({ query: 'search_ioc', search_term: q.toLowerCase() });
    } else {
      const body = { query: 'search_ioc', search_term: q };
      const tfType = tfIocTypeMap[type];
      if (tfType) body.ioc_type = tfType;
      data = await tfPost(body);
    }

    return res.status(200).json(data ?? EMPTY);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
