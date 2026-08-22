
/* ── BYOK key storage (prefix: iv_) ─────────────────────────────────────── */
function getKey(service) {
  try { return (localStorage.getItem(`iv_${service}_key`) || '').trim(); } catch(_) { return ''; }
}

const SERVER_BASE = (() => {
  const isStatic = ['github.io','netlify.app','pages.dev'].some(h => location.hostname.endsWith(h));
  return isStatic ? 'https://ioc-verdikt.vercel.app' : '';
})();

function vtUrlId(url) {
  try { return btoa(url).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }
  catch(_) {
    /* non-Latin1: percent-encode first */
    return btoa(encodeURIComponent(url)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  }
}

/* ── API ──────────────────────────────────────────────────────────────────
   Two call paths:
   1. DIRECT-FROM-BROWSER (open CORS), OTX, URLScan, IPLocate.
      Vendor URL called straight from here with the user's key attached
      exactly the way that vendor documents. No relay involved.
   2. VIA RELAY (/api/{vendor}), VT, AbuseIPDB, ThreatFox, URLhaus,
      MalwareBazaar, HybridAnalysis, FileScan. The user's key is attached
      as the `x-user-key` request header on every call, never as a query
      param on our own relay (log-leak risk). The relay function reads
      that header and forwards it to the vendor server-side.
   ───────────────────────────────────────────────────────────────────────── */
const API = {

  /* ── DIRECT ────────────────────────────────────────────────────────── */

  async otx(ioc, signal) {
    const key = getKey('otx');
    if (!key) return { source: 'otx', noKey: true };
    const t = ioc.type;
    let section;
    if (t === 'ip')                 section = `IPv4/${encodeURIComponent(ioc.value)}`;
    else if (t === 'ipv6')          section = `IPv6/${encodeURIComponent(ioc.value)}`;
    else if (t === 'domain')        section = `domain/${encodeURIComponent(ioc.value)}`;
    else if (t === 'url')           section = `url/${encodeURIComponent(ioc.value)}`;
    else if (t.startsWith('hash_')) section = `file/${encodeURIComponent(ioc.value)}`;
    else return { source: 'otx', skipped: true, reason: 'Unsupported type' };
    try {
      const resp = await fetch(`https://otx.alienvault.com/api/v1/indicators/${section}/general`, {
        signal, headers: { 'X-OTX-API-KEY': key },
      });
      if (!resp.ok) return otxHttpErr(resp.status);
      return parseOTXResponse(await resp.json(), t, ioc.value);
    } catch(e) { return { source: 'otx', error: fmtErr(e) }; }
  },

  async urlscan(ioc, signal) {
    const key = getKey('urlscan');
    if (!key) return { source: 'urlscan', noKey: true };
    const t = ioc.type;
    if (t.startsWith('hash_'))
      return { source: 'urlscan', skipped: true, reason: 'N/A for hashes' };
    let q;
    if (t === 'ip' || t === 'ipv6') q = `ip:${ioc.value}`;
    else if (t === 'domain')        q = `domain:${ioc.value}`;
    else if (t === 'url')           q = `page.url:"${ioc.value}"`;
    else return { source: 'urlscan', skipped: true, reason: 'Unsupported type' };
    try {
      const resp = await fetch(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}`, {
        signal, headers: { 'API-Key': key },
      });
      if (!resp.ok) return { source: 'urlscan', error: `HTTP ${resp.status}` };
      return parseURLScanResponse(await resp.json(), q);
    } catch(e) { return { source: 'urlscan', error: fmtErr(e) }; }
  },

  async iplocate(ioc, signal) {
    const key = getKey('iplocate');
    if (!key) return { source: 'iplocate', noKey: true };
    const t = ioc.type;
    if (t !== 'ip' && t !== 'ipv6')
      return { source: 'iplocate', skipped: true, reason: 'IP only' };
    try {
      const resp = await fetch(`https://www.iplocate.io/api/lookup/${encodeURIComponent(ioc.value)}`, {
        signal, headers: { 'X-Api-Key': key },
      });
      if (resp.status === 404) return { source: 'iplocate', notFound: true };
      if (!resp.ok) return { source: 'iplocate', error: `HTTP ${resp.status}` };
      return parseIPLocateResponse(await resp.json());
    } catch(e) { return { source: 'iplocate', error: fmtErr(e) }; }
  },

  /* ── VIA RELAY ─────────────────────────────────────────────────────── */

  async virusTotal(ioc, signal) {
    const key = getKey('vt');
    if (!key) return { source: 'virustotal', noKey: true };
    let path;
    const t = ioc.type;
    if (t === 'ip' || t === 'ipv6')   path = `/api/v3/ip_addresses/${encodeURIComponent(ioc.value)}`;
    else if (t === 'domain')          path = `/api/v3/domains/${encodeURIComponent(ioc.value)}`;
    else if (t === 'url')             path = `/api/v3/urls/${vtUrlId(ioc.value)}`;
    else if (t.startsWith('hash_'))   path = `/api/v3/files/${encodeURIComponent(ioc.value)}`;
    else return { source: 'virustotal', skipped: true, reason: 'Unsupported type' };
    try {
      const resp = await fetch(`${SERVER_BASE}/api/vt?path=${encodeURIComponent(path)}`, {
        signal, headers: { 'x-user-key': key },
      });
      if (!resp.ok) return vtHttpErr(resp.status);
      return parseVTResponse(await resp.json(), t);
    } catch(e) { return { source: 'virustotal', error: fmtErr(e) }; }
  },

  async abuseIPDB(ioc, signal) {
    const key = getKey('abuseipdb');
    if (!key) return { source: 'abuseipdb', noKey: true };
    if (ioc.type !== 'ip' && ioc.type !== 'ipv6')
      return { source: 'abuseipdb', skipped: true, reason: 'IP only' };
    try {
      const resp = await fetch(`${SERVER_BASE}/api/abuseipdb?ip=${encodeURIComponent(ioc.value)}`, {
        signal, headers: { 'x-user-key': key },
      });
      if (!resp.ok) return abHttpErr(resp.status);
      return parseAbuseIPDBResponse(await resp.json());
    } catch(e) { return { source: 'abuseipdb', error: fmtErr(e) }; }
  },

  async threatfox(ioc, signal) {
    const key = getKey('threatfox');
    if (!key) return { source: 'threatfox', noKey: true };
    try {
      const resp = await fetch(`${SERVER_BASE}/api/threatfox?q=${encodeURIComponent(ioc.value)}&type=${ioc.type}`, {
        signal, headers: { 'x-user-key': key },
      });
      if (!resp.ok) return { source: 'threatfox', error: `HTTP ${resp.status}` };
      return parseThreatFoxResponse(await resp.json(), ioc.value);
    } catch(e) { return { source: 'threatfox', error: fmtErr(e) }; }
  },

  async urlhaus(ioc, signal) {
    const key = getKey('urlhaus');
    if (!key) return { source: 'urlhaus', noKey: true };
    const t = ioc.type;
    let param;
    if (t === 'ip' || t === 'ipv6' || t === 'domain') param = `host=${encodeURIComponent(ioc.value)}`;
    else if (t === 'url')           param = `url=${encodeURIComponent(ioc.value)}`;
    else if (t === 'hash_md5')      param = `md5=${encodeURIComponent(ioc.value)}`;
    else if (t === 'hash_sha256')   param = `sha256=${encodeURIComponent(ioc.value)}`;
    else return { source: 'urlhaus', skipped: true, reason: 'Hash type not supported' };
    try {
      const resp = await fetch(`${SERVER_BASE}/api/urlhaus?${param}`, {
        signal, headers: { 'x-user-key': key },
      });
      if (!resp.ok) return { source: 'urlhaus', error: `HTTP ${resp.status}` };
      return parseURLhausResponse(await resp.json(), t, ioc.value);
    } catch(e) { return { source: 'urlhaus', error: fmtErr(e) }; }
  },

  async malwarebazaar(ioc, signal) {
    const key = getKey('malwarebazaar');
    if (!key) return { source: 'malwarebazaar', noKey: true };
    const t = ioc.type;
    let param;
    if (t.startsWith('hash_')) param = `hash=${encodeURIComponent(ioc.value)}`;
    else if (t === 'ip' || t === 'ipv6') param = `tag=${encodeURIComponent(ioc.value)}`;
    else return { source: 'malwarebazaar', skipped: true, reason: 'IP/hash only' };
    try {
      const resp = await fetch(`${SERVER_BASE}/api/malwarebazaar?${param}`, {
        signal, headers: { 'x-user-key': key },
      });
      if (!resp.ok) return { source: 'malwarebazaar', error: `HTTP ${resp.status}` };
      return parseMBResponse(await resp.json(), t, ioc.value);
    } catch(e) { return { source: 'malwarebazaar', error: fmtErr(e) }; }
  },

  async hybridanalysis(ioc, signal) {
    const key = getKey('hybridanalysis');
    if (!key) return { source: 'hybridanalysis', noKey: true };
    const t = ioc.type;
    let param;
    if (t === 'ip')               param = `ip=${encodeURIComponent(ioc.value)}`;
    else if (t === 'hash_md5')    param = `hash=${encodeURIComponent(ioc.value)}&htype=md5`;
    else if (t === 'hash_sha1')   param = `hash=${encodeURIComponent(ioc.value)}&htype=sha1`;
    else if (t === 'hash_sha256') param = `hash=${encodeURIComponent(ioc.value)}&htype=sha256`;
    else return { source: 'hybridanalysis', skipped: true, reason: t === 'hash_sha512' ? 'SHA-512 not supported' : 'IP/hash only' };
    try {
      const resp = await fetch(`${SERVER_BASE}/api/hybridanalysis?${param}`, {
        signal, headers: { 'x-user-key': key },
      });
      if (!resp.ok) return { source: 'hybridanalysis', error: `HTTP ${resp.status}` };
      return parseHybridAnalysisResponse(await resp.json());
    } catch(e) { return { source: 'hybridanalysis', error: fmtErr(e) }; }
  },

  async filescan(ioc, signal) {
    const key = getKey('filescan');
    if (!key) return { source: 'filescan', noKey: true };
    const t = ioc.type;
    if (!t.startsWith('hash_'))
      return { source: 'filescan', skipped: true, reason: 'Hash only' };
    try {
      const resp = await fetch(`${SERVER_BASE}/api/filescan?hash=${encodeURIComponent(ioc.value)}`, {
        signal, headers: { 'x-user-key': key },
      });
      if (!resp.ok) return { source: 'filescan', error: `HTTP ${resp.status}` };
      return parseFileScanResponse(await resp.json());
    } catch(e) { return { source: 'filescan', error: fmtErr(e) }; }
  },
};


/* ── VT parser ──────────────────────────────────────────────────────────── */
function parseVTResponse(data, iocType) {
  const attrs = data?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const mal = stats.malicious || 0, sus = stats.suspicious || 0;
  const harm = stats.harmless || 0, undet = stats.undetected || 0;
  const total = mal + sus + harm + undet;
  const scanDate = attrs.last_analysis_date
    ? new Date(attrs.last_analysis_date * 1000).toISOString().split('T')[0] : null;

  const base = {
    source: 'virustotal',
    malicious: mal, suspicious: sus, harmless: harm, undetected: undet, total,
    reputation: attrs.reputation ?? null,
    tags: attrs.tags || [],
    last_analysis_date: scanDate,
  };

  if (iocType === 'ip' || iocType === 'ipv6') {
    const cert = attrs.last_https_certificate || null;
    return {
      ...base,
      ip: data?.data?.id || '',
      asn: attrs.asn ?? null,
      as_owner: attrs.as_owner || null,
      country: attrs.country || null,
      jarm: attrs.jarm || null,
      network: attrs.network || null,
      cert_subject_cn: cert?.subject?.CN || null,
      cert_issuer_cn: cert?.issuer?.CN || null,
      cert_self_signed: cert ? (cert.self_signed ?? null) : null,
      cert_thumbprint: cert?.thumbprint_sha256 || null,
      cert_valid_until: cert?.validity?.not_after || null,
      link: data?.data?.id ? `https://www.virustotal.com/gui/ip-address/${data.data.id}` : null,
      raw: data,
    };
  }
  if (iocType === 'domain') {
    const cert = attrs.last_https_certificate || null;
    const cats = attrs.categories ? Object.values(attrs.categories).slice(0, 3).join(', ') : null;
    return {
      ...base,
      domain: data?.data?.id || '',
      registrar: attrs.registrar || null,
      categories: cats,
      cert_subject_cn: cert?.subject?.CN || null,
      cert_issuer_cn: cert?.issuer?.CN || null,
      cert_valid_until: cert?.validity?.not_after || null,
      link: data?.data?.id ? `https://www.virustotal.com/gui/domain/${data.data.id}` : null,
      raw: data,
    };
  }
  if (iocType === 'url') {
    return {
      ...base,
      url: attrs.url || data?.data?.id || '',
      finalUrl: attrs.last_final_url || null,
      title: attrs.title || null,
      categories: attrs.categories ? Object.values(attrs.categories).slice(0, 3).join(', ') : null,
      link: data?.data?.id ? `https://www.virustotal.com/gui/url/${data.data.id}` : null,
      raw: data,
    };
  }
  if (iocType.startsWith('hash_')) {
    return {
      ...base,
      md5: attrs.md5 || null,
      sha1: attrs.sha1 || null,
      sha256: attrs.sha256 || null,
      sha512: attrs.sha512 || null,
      name: attrs.meaningful_name || (attrs.names || [])[0] || null,
      size: attrs.size != null ? `${(attrs.size / 1024).toFixed(1)} KB` : null,
      fileType: attrs.type_description || attrs.magic || null,
      firstSeen: attrs.first_submission_date
        ? new Date(attrs.first_submission_date * 1000).toISOString().split('T')[0] : null,
      link: attrs.sha256 ? `https://www.virustotal.com/gui/file/${attrs.sha256}` : null,
      raw: data,
    };
  }
  return { ...base, raw: data };
}

/* ── OTX parser ─────────────────────────────────────────────────────────── */
function parseOTXResponse(data, iocType, iocValue) {
  const pulseCount = data?.pulse_info?.count || 0;
  const pulses = data?.pulse_info?.pulses || [];
  let totalSubscribers = 0, maxIndicatorCount = 0;
  const pulseAuthors = [], malwareFamilies = [], tags = [], adversaries = [];
  for (const p of pulses) {
    totalSubscribers += p.subscriber_count || 0;
    if ((p.indicator_count || 0) > maxIndicatorCount) maxIndicatorCount = p.indicator_count;
    if (p.author_name) pulseAuthors.push(p.author_name);
  }
  for (const p of pulses.slice(0, 5)) {
    if (p.malware_families) malwareFamilies.push(...p.malware_families.map(f => f.display_name || f));
    if (p.tags) tags.push(...p.tags.slice(0, 3));
    if (p.adversary) adversaries.push(p.adversary);
  }

  const otxSection = { ip: 'ip', ipv6: 'ipv6', domain: 'domain', url: 'url' };
  const linkBase = otxSection[iocType] || 'file';
  const linkVal  = iocType === 'url' ? encodeURI(iocValue) : iocValue;

  return {
    source: 'otx',
    pulseCount,
    subscriberCount: totalSubscribers,
    indicatorCount: maxIndicatorCount,
    validation: (data?.validation || []).length > 0 ? 'Validated' : 'Unvalidated',
    pulseSources: [...new Set(pulseAuthors)].slice(0, 5),
    malwareFamilies: [...new Set(malwareFamilies)].slice(0, 5),
    tags: [...new Set(tags)].slice(0, 8),
    adversaries: [...new Set(adversaries)].slice(0, 3),
    recentPulse: pulses[0]?.name || null,
    link: `https://otx.alienvault.com/indicator/${linkBase}/${linkVal}`,
    raw: data,
  };
}

/* ── AbuseIPDB parser ────────────────────────────────────────────────────── */
function parseAbuseIPDBResponse(data) {
  const d = data?.data || {};
  return {
    source: 'abuseipdb',
    score: d.abuseConfidenceScore || 0,
    ipAddress: d.ipAddress || '',
    isPublic: d.isPublic ?? null,
    ipVersion: d.ipVersion ?? null,
    isWhitelisted: d.isWhitelisted ?? null,
    usageType: d.usageType || null,
    isp: d.isp || null,
    domain: d.domain || null,
    hostnames: d.hostnames || [],
    isTor: d.isTor || false,
    totalReports: d.totalReports || 0,
    lastReportedAt: d.lastReportedAt || null,
    link: d.ipAddress ? `https://www.abuseipdb.com/check/${d.ipAddress}` : null,
    raw: data,
  };
}

/* ── URLScan parser ──────────────────────────────────────────────────────── */
function parseURLScanResponse(data, searchQ) {
  const results = data?.results || [];
  const total = data?.total || results.length;
  if (!total && !results.length) return { source: 'urlscan', notFound: true, total: 0, results: [], flaggedCount: 0, raw: data };
  /* The /search/ endpoint's result items carry no verdicts/score field at all
     (that only exists on the full /result/{uuid}/ report), confirmed live.
     task.tags is the only per-item signal available; use community tags like
     "malicious"/"phishing"/"suspicious" as the flag instead of a score. */
  const FLAG_TAGS = new Set(['malicious', 'phishing', 'suspicious']);
  const isFlagged = r => (r.task?.tags || []).some(t => FLAG_TAGS.has(String(t).toLowerCase()));
  const flaggedCount = results.filter(isFlagged).length;
  const recent = results.slice(0, 5).map(r => ({
    url: r.page?.url || '',
    domain: r.page?.domain || '',
    date: r.task?.time?.split('T')[0] || '',
    flagged: isFlagged(r),
  }));
  return {
    source: 'urlscan', total, flaggedCount, recent, notFound: false,
    link: searchQ ? `https://urlscan.io/search/#${encodeURIComponent(searchQ)}` : null,
    raw: data,
  };
}

/* ── ThreatFox parser ────────────────────────────────────────────────────── */
function parseThreatFoxResponse(data, iocValue) {
  if (data?.query_status === 'no_result' || !data?.data?.length)
    return { source: 'threatfox', notFound: true, iocCount: 0, raw: data };
  const iocs = data.data || [];
  const top = iocs[0] || {};
  return {
    source: 'threatfox',
    iocCount: iocs.length,
    malwareFamilies: [...new Set(iocs.map(i => i.malware).filter(Boolean))],
    threatTypes: [...new Set(iocs.map(i => i.threat_type).filter(Boolean))],
    maxConfidence: Math.max(...iocs.map(i => i.confidence_level || 0), 0),
    notFound: false,
    firstSeen: iocs[0]?.first_seen?.split(' ')[0] || null,
    lastSeen: iocs[0]?.last_seen?.split(' ')[0] || null,
    reporter: top.reporter || null,
    reference: top.reference || null,
    tags: [...new Set(iocs.slice(0, 5).flatMap(i => i.tags || []))].slice(0, 10),
    malwareAlias: top.malware_alias || null,
    malpediaLink: top.malware_malpedia || null,
    iocTypeDesc: top.ioc_type_desc || null,
    link: iocValue ? `https://threatfox.abuse.ch/browse.php?search=${encodeURIComponent('ioc:' + iocValue)}` : null,
    raw: data,
  };
}

/* ── URLhaus parsers ─────────────────────────────────────────────────────── */
function parseURLhausResponse(data, iocType, iocValue) {
  const uhLink = iocValue ? `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(iocValue)}` : null;

  if (iocType === 'url') {
    if (!data?.id || data?.query_status === 'no_results')
      return { source: 'urlhaus', notFound: true, urlsCount: 0, raw: data };
    return {
      source: 'urlhaus',
      urlsCount: 1,
      onlineCount: data.url_status === 'online' ? 1 : 0,
      threats: data.threat ? [data.threat] : [],
      notFound: false,
      tags: data.tags || [],
      dateAdded: data.date_added?.split(' ')[0] || null,
      link: data.id ? `https://urlhaus.abuse.ch/url/${data.id}/` : uhLink,
      raw: data,
    };
  }
  if (iocType === 'hash_md5' || iocType === 'hash_sha256') {
    if (data?.query_status !== 'ok')
      return { source: 'urlhaus', notFound: true, urlsCount: 0, raw: data };
    return {
      source: 'urlhaus',
      urlsCount: data.url_count || 0,
      onlineCount: 0,
      threats: data.signature ? [data.signature] : [],
      notFound: false,
      /* /v1/payload/ has no tags field anywhere in its response, top-level
         or per-url, unlike the url/host endpoints, confirmed against the
         vendor's own documented schema. */
      tags: [],
      dateAdded: data.firstseen?.split(' ')[0] || null,
      link: uhLink,
      raw: data,
    };
  }
  /* host lookup (IP/IPv6/domain) */
  if (data?.query_status === 'no_results')
    return { source: 'urlhaus', notFound: true, urlsCount: 0, raw: data };
  const urls = data?.urls || [];
  return {
    source: 'urlhaus',
    urlsCount: urls.length,
    onlineCount: urls.filter(u => u.url_status === 'online').length,
    threats: [...new Set(urls.map(u => u.threat).filter(Boolean))],
    /* tags live per-url on /v1/host/ (urls[].tags), there is no top-level
       data.tags on this endpoint, confirmed against the vendor's own
       documented schema, that field was always silently empty before. */
    notFound: false, tags: [...new Set(urls.flatMap(u => u.tags || []))],
    dateAdded: urls[0]?.date_added?.split(' ')[0] || null,
    link: uhLink,
    raw: data,
  };
}

/* ── MalwareBazaar parser (hash + IP/IPv6 tag search) ────────────────────── */
function parseMBResponse(data, iocType, iocValue) {
  if (iocType.startsWith('hash_')) {
    if (data?.query_status !== 'ok' || !data?.data?.length)
      return { source: 'malwarebazaar', notFound: true, count: 0, raw: data };
    const item = data.data[0];
    const signer = Array.isArray(item.code_sign) ? item.code_sign[0] : null;
    return {
      source: 'malwarebazaar',
      count: 1,
      families: item.signature ? [item.signature] : [],
      fileName: item.file_name || null,
      fileType: item.file_type_mime || null,
      firstSeen: item.first_seen?.split(' ')[0] || null,
      codeSignSubject: signer?.subject_cn || null,
      codeSignIssuer: signer?.issuer_cn || null,
      codeSignValidTo: signer?.valid_to || null,
      yaraRules: Array.isArray(item.yara_rules) ? item.yara_rules.map(y => y.rule_name).filter(Boolean).slice(0, 8) : [],
      link: item.sha256_hash ? `https://bazaar.abuse.ch/sample/${item.sha256_hash}/` : null,
      notFound: false,
      raw: data,
    };
  }
  /* tag search (IP/IPv6) */
  if (data?.query_status !== 'ok' || !data?.data?.length)
    return { source: 'malwarebazaar', notFound: true, count: 0, raw: data };
  const items = data.data || [];
  return {
    source: 'malwarebazaar',
    count: items.length,
    families: [...new Set(items.map(i => i.signature).filter(Boolean))].slice(0, 5),
    link: iocValue ? `https://bazaar.abuse.ch/browse.php?search=tag%3A${encodeURIComponent(iocValue)}` : null,
    notFound: false, raw: data,
  };
}

/* ── HybridAnalysis parser ───────────────────────────────────────────────── */
function parseHybridAnalysisResponse(data) {
  const results = Array.isArray(data) ? data : (data?.result || data?.results || data?.reports || []);
  const ov = Array.isArray(data) ? {} : data;

  if (!results.length && !ov.verdict && !ov.sha256)
    return { source: 'hybridanalysis', notFound: true, count: 0, raw: data };

  const maliciousCount = results.filter(r => r.verdict === 'malicious' || (r.threat_level || 0) >= 2).length;
  const rawMaxScore    = Math.max(...results.map(r => r.threat_score || 0), ov.threat_score || 0);
  const maxScore       = rawMaxScore > 0 ? rawMaxScore : null;

  const topReport = results.find(r => (r.threat_level || 0) >= 2)
    || results.find(r => (r.threat_level || 0) >= 1)
    || results[0] || {};

  const families = [...new Set([
    ov.vx_family, ov.malware_family,
    ...results.slice(0, 8).flatMap(r => [r.vx_family, r.malware_family]),
  ].filter(Boolean))].slice(0, 5);

  const tags = [...new Set([
    ...(ov.classification_tags || []),
    ...results.slice(0, 5).flatMap(r => r.classification_tags || []),
  ].filter(Boolean))].slice(0, 10);

  const environments = [...new Set(
    results.map(r => r.environment_description).filter(Boolean)
  )].slice(0, 4);

  const submitNames = [...new Set(
    results.map(r => r.submit_name).filter(Boolean)
  )].slice(0, 3);

  const fileTypes = [...new Set([
    ...(ov.type_short || []),
    ...results.flatMap(r => r.type_short || []),
  ].filter(Boolean))].slice(0, 3);

  const size = ov.size
    ? (ov.size >= 1048576 ? `${(ov.size/1048576).toFixed(1)} MB` : `${(ov.size/1024).toFixed(1)} KB`)
    : null;

  /* Same pool the modal builder uses (top 5 per-environment reports plus
     the overview object), promoted here so MITRE/network-IOC/signature
     data reaches export and isn't modal-only. */
  const pool = results.slice(0, 5).concat(ov);

  const avDetect = pool.map(r => r?.av_detect).find(v => typeof v === 'number') ?? null;

  const mitreMap = new Map();
  pool.forEach(r => (Array.isArray(r?.mitre_attcks) ? r.mitre_attcks : []).forEach(m => {
    const key = m?.attck_id || m?.technique_id || m?.technique;
    if (key && !mitreMap.has(key)) mitreMap.set(key, m);
  }));
  const mitreAttacks = [...mitreMap.values()].slice(0, 8).map(m => {
    const id = m.attck_id || m.technique_id, name = m.technique;
    return id && name ? `${id} - ${name}` : (id || name || 'Unknown');
  });

  const networkIOCs = [...new Set(pool.flatMap(r => [
    ...(Array.isArray(r?.hosts) ? r.hosts : []),
    ...(Array.isArray(r?.domains) ? r.domains : []),
    ...(Array.isArray(r?.compromised_hosts) ? r.compromised_hosts : []),
  ]).filter(Boolean))].slice(0, 8);

  const signatures = [...new Set(
    pool.flatMap(r => (Array.isArray(r?.signatures) ? r.signatures : []).map(s => s?.name || s?.description)).filter(Boolean)
  )].slice(0, 6);

  return {
    source: 'hybridanalysis',
    count: results.length || (ov.sha256 ? 1 : 0),
    maliciousCount, maxScore,
    verdict: ov.verdict || topReport?.verdict || null,
    families, tags, environments, submitNames, fileTypes, size,
    avDetect, mitreAttacks, networkIOCs, signatures,
    sha256: ov.sha256 || topReport?.sha256 || null,
    md5:    ov.md5    || topReport?.md5    || null,
    sha1:   ov.sha1   || topReport?.sha1   || null,
    link: (ov.sha256 || topReport?.sha256) ? `https://www.hybrid-analysis.com/sample/${ov.sha256 || topReport.sha256}` : null,
    notFound: false, raw: data,
  };
}

/* ── FileScan parser ─────────────────────────────────────────────────────── */
/* Field paths confirmed against a live /api/reports/search response (not
   docs, the public OpenAPI spec has no per-field descriptions): each item
   is {id, file:{name,mime_type,short_type,sha256,link}, state, verdict,
   tags:[{source, sourceIdentifier, isRootTag, isMalwareFamilyTag,
   tag:{name, synonyms, descriptions, verdict:{verdict,threatLevel,
   confidence}}}], date, uploader, updated_date}. verdict/malware-family
   live at item/tag level, not under item.file, and item.tags is an array
   of objects (tag name is at t.tag.name), not an array of strings. */
function parseFileScanResponse(data) {
  const items = data?.items || [];
  const count = data?.count || items.length;
  if (!count) return { source: 'filescan', notFound: true, count: 0, raw: data };

  const VERDICT_RANK = { malicious: 5, likely_malicious: 4, suspicious: 3, unknown: 1, no_threat: 0, benign: 0 };
  const maliciousCount = items.filter(i => i.verdict === 'malicious' || i.verdict === 'likely_malicious').length;
  const verdicts = [...new Set(items.map(i => i.verdict).filter(Boolean))]
    .sort((a, b) => (VERDICT_RANK[b] ?? 0) - (VERDICT_RANK[a] ?? 0))
    .slice(0, 3);
  const families = [...new Set(
    items.flatMap(i => (i.tags || []).filter(t => t.isMalwareFamilyTag).map(t => t.tag?.name)).filter(Boolean)
  )].slice(0, 5);

  /* filescan.io has no public /search page (confirmed live, /search and
     /search-result both fail, one 404s outright, the other redirects to a
     sign-in wall), the only confirmed-public, no-login URL is a specific
     report's own page at /uploads/{scan_init.id}/reports/{item.id}/overview.
     Link to the highest-severity matching report rather than a search. */
  const topItem = items.find(i => i.verdict === verdicts[0]) || items[0];
  const reportLink = (topItem?.scan_init?.id && topItem?.id)
    ? `https://www.filescan.io/uploads/${topItem.scan_init.id}/reports/${topItem.id}/overview`
    : null;

  return {
    source: 'filescan',
    count, maliciousCount, verdicts, topVerdict: verdicts[0] || null, families,
    notFound: false,
    link: reportLink,
    raw: data,
  };
}

/* ── IPLocate parser ─────────────────────────────────────────────────────── */
function parseIPLocateResponse(data) {
  if (!data || data.error) return { source: 'iplocate', error: data?.error || 'No data' };
  const asnObj  = (data.asn && typeof data.asn === 'object')     ? data.asn     : {};
  const company = (data.company && typeof data.company === 'object') ? data.company : {};
  const p       = (data.privacy && typeof data.privacy === 'object') ? data.privacy : {};
  const nn = v => (v && v !== 'null' && v !== 'none') ? v : null;
  return {
    source:          'iplocate',
    ip:              data.ip           || null,
    country:         data.country      || null,
    country_code:    data.country_code || null,
    city:            data.city         || null,
    subdivision:     data.subdivision  || null,
    continent:       data.continent    || null,
    latitude:        data.latitude     ?? null,
    longitude:       data.longitude    ?? null,
    time_zone:       data.time_zone    || null,
    postal_code:     data.postal_code  || null,
    network:         asnObj.route      || null,
    asn:             asnObj.asn        || null,
    asn_name:        asnObj.name       || null,
    isp:             asnObj.name       || company.name || null,
    organization:    company.name      || asnObj.name  || null,
    domain:          nn(asnObj.domain) || nn(company.domain) || null,
    is_abuser:       p.is_abuser       ?? false,
    is_anonymous:    p.is_anonymous    ?? false,
    is_vpn:          p.is_vpn          ?? false,
    is_proxy:        p.is_proxy        ?? false,
    is_tor:          p.is_tor          ?? false,
    is_hosting:      p.is_hosting      ?? false,
    is_icloud_relay: p.is_icloud_relay ?? false,
    is_bogon:        p.is_bogon        ?? false,
    link: data.ip ? `https://www.iplocate.io/ip/${data.ip}` : null,
    raw: data,
  };
}

/* ── Error helpers ───────────────────────────────────────────────────────── */
function vtHttpErr(s)  { return { source: 'virustotal',  error: { 400:'Missing/invalid key', 404: 'Not found', 401: 'Unauthorized', 429: 'Rate limited' }[s] || `HTTP ${s}` }; }
function abHttpErr(s)  { return { source: 'abuseipdb',   error: { 400:'Missing/invalid key', 401: 'Unauthorized', 429: 'Rate limited' }[s] || `HTTP ${s}` }; }
function otxHttpErr(s) { return { source: 'otx',         error: { 401: 'Unauthorized', 404: 'Not found', 429: 'Rate limited' }[s] || `HTTP ${s}` }; }
function fmtErr(e)     { return e?.name === 'AbortError' ? 'Timeout (10s)' : e?.message?.match(/fetch|network|load/i) ? 'Network error' : (e.message || 'Unknown error'); }
