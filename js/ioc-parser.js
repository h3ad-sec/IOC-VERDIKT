
// 4+ char TLDs. 2-char (ccTLDs) and 3-char (com/net/org/etc.) are always valid.
const KNOWN_TLDS_4PLUS = new Set([
  'info','mobi','name','arpa','coop','aero','jobs','post',
  'online','store','site','tech','app','dev','blog','news',
  'cloud','media','live','click','link','space','zone','plus',
  'club','guru','work','works','tools','tips','ninja','rocks',
  'world','global','group','solutions','services','systems',
  'software','support','agency','digital','network','center',
  'today','expert','email','social','studio','design','photo',
  'video','music','health','care','bank','cash','money',
  'finance','trade','market','travel','hotel','tours','rent',
  'sale','deals','legal','computer','hosting','server',
  'security','academy','school','college','university',
  'education','training','institute','foundation','company',
  'business','management','consulting','engineering','science',
  'research','technology','industrial','international',
  'government','community','family','church','charity','shop',
  'game','games','onion','i2p','local','asia','porn','adult',
  'sexy','dating','casino','poker','free','best','news','live',
  'stream','racing','trade','review','win','loan','work','men',
  'diet','click','download','accountant','cricket','country',
  'webcam','faith','science','party','stream','rocks','band',
  'property','report','expert','pizza','beer','kitchen','yoga',
  'solar','repair','cleaning','plumbing','gallery','tattoo',
  'camera','equipment','lighting','directory','glass','exposed',
  'auction','democrat','republican','voting','tax',
  'mortgage','loans','attorney','lawyer','court',
]);

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV6_RE = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}/g;

const PRIVATE_V4 = [
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^127\.\d+\.\d+\.\d+$/,
  /^0\.0\.0\.0$/,
  /^169\.254\.\d+\.\d+$/,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+$/,
  /^255\.255\.255\.255$/,
];

function isPrivateV4(ip) { return PRIVATE_V4.some(r => r.test(ip)); }
function isPrivateV6(ip) {
  const l = ip.toLowerCase();
  return l === '::1' || l.startsWith('fe80:') || l.startsWith('fc') || l.startsWith('fd');
}

function defangAll(raw) {
  return raw
    .replace(/hxxps/gi, 'https')
    .replace(/hxxp/gi, 'http')
    .replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.')
    .replace(/\[dot\]/gi, '.').replace(/\(dot\)/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[at\]/gi, '@');
}

function parseIOCsWithMeta(raw) {
  const text = defangAll(raw);
  const seen = new Set();
  const iocs = [];

  /* 1. Hashes — longest first so SHA512 claims tokens before SHA256/SHA1/MD5 */
  for (const [re, type, label] of [
    [/\b[0-9a-fA-F]{128}\b/g, 'hash_sha512', 'SHA-512'],
    [/\b[0-9a-fA-F]{64}\b/g,  'hash_sha256', 'SHA-256'],
    [/\b[0-9a-fA-F]{40}\b/g,  'hash_sha1',   'SHA-1'],
    [/\b[0-9a-fA-F]{32}\b/g,  'hash_md5',    'MD5'],
  ]) {
    for (const m of text.matchAll(new RegExp(re.source, 'g'))) {
      const v = m[0].toLowerCase();
      if (!seen.has(v)) { seen.add(v); iocs.push({ value: v, type, label }); }
    }
  }

  /* 2. URLs */
  for (const m of text.matchAll(/https?:\/\/[^\s"'<>\[\]{}|\\^`]+/gi)) {
    let v = m[0].replace(/[.,;:!?)\]>]+$/, '');
    if (!seen.has(v)) { seen.add(v); iocs.push({ value: v, type: 'url', label: 'URL' }); }
  }

  /* 3. IPv4 */
  for (const m of text.matchAll(new RegExp(IPV4_RE.source, 'g'))) {
    const v = m[0];
    if (!seen.has(v)) {
      seen.add(v);
      iocs.push({ value: v, type: 'ip', label: 'IPv4', isPrivate: isPrivateV4(v) });
    }
  }

  /* 4. IPv6 */
  for (const m of text.matchAll(new RegExp(IPV6_RE.source, 'g'))) {
    const v = m[0];
    if (!seen.has(v) && v.includes(':') && v.length > 6) {
      seen.add(v);
      iocs.push({ value: v, type: 'ipv6', label: 'IPv6', isPrivate: isPrivateV6(v) });
    }
  }

  /* 5. Domains — after IPs so numeric-only dotted strings stay as IPs */
  const domainRe = /\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
  for (const m of text.matchAll(domainRe)) {
    const v = m[0].toLowerCase();
    if (seen.has(v)) continue;
    const labels = v.split('.');
    const tld = labels[labels.length - 1];
    /* skip if all non-TLD labels are pure digits (version strings, stray IP fragments) */
    if (labels.slice(0, -1).every(l => /^\d+$/.test(l))) continue;
    /* skip unknown 4+ char TLDs — prevents usernames like ram.charan, hrushikesh.badgujar */
    if (tld.length > 3 && !KNOWN_TLDS_4PLUS.has(tld)) continue;
    seen.add(v);
    iocs.push({ value: v, type: 'domain', label: 'Domain' });
  }

  const byType = {
    ip:     iocs.filter(i => i.type === 'ip').length,
    ipv6:   iocs.filter(i => i.type === 'ipv6').length,
    domain: iocs.filter(i => i.type === 'domain').length,
    url:    iocs.filter(i => i.type === 'url').length,
    hash:   iocs.filter(i => i.type.startsWith('hash_')).length,
  };

  return { iocs, total: iocs.length, byType, private: iocs.filter(i => i.isPrivate).length };
}

function parseIOCsRealtime() {
  const mode = (typeof currentMode !== 'undefined') ? currentMode : 'all';

  const raw = document.getElementById('ioc-input')?.value || '';
  const meta = parseIOCsWithMeta(raw);
  const info = document.getElementById('ioc-parsed-info');
  const btn  = document.getElementById('scan-btn');

  /* Update per-mode badge counts in the mode-tab blocks */
  const byMode = {
    all:    meta.total,
    ip:     meta.byType.ip + meta.byType.ipv6,
    hash:   meta.byType.hash,
    domain: meta.byType.domain + meta.byType.url,
  };

  for (const [m, n] of Object.entries(byMode)) {
    const el = document.getElementById(`mcount-${m}`);
    if (el) el.textContent = n > 0 ? `${n} IOC${n > 1 ? 's' : ''}` : '';
  }

  /* Filter for the active mode */
  const filtered = (typeof filterIOCsByMode === 'function') ? filterIOCsByMode(meta.iocs, mode) : meta.iocs;

  if (filtered.length === 0) {
    if (info) {
      if (meta.total > 0 && mode !== 'all') {
        const cfg = (typeof MODE_CONFIG !== 'undefined') ? MODE_CONFIG[mode] : null;
        info.innerHTML = `<span style="color:var(--yellow)">0 ${cfg?.label || ''} IOCs in input</span>`;
      } else {
        info.innerHTML = '';
      }
    }
    if (btn) btn.disabled = true;
    return;
  }

  const bt = {
    ip:     filtered.filter(i => i.type === 'ip').length,
    ipv6:   filtered.filter(i => i.type === 'ipv6').length,
    domain: filtered.filter(i => i.type === 'domain').length,
    url:    filtered.filter(i => i.type === 'url').length,
    hash:   filtered.filter(i => i.type.startsWith('hash_')).length,
  };
  const parts = [`<span>${filtered.length}</span> IOC${filtered.length > 1 ? 's' : ''}`];
  const labels = [];
  if (bt.ip)     labels.push(`${bt.ip} IPv4`);
  if (bt.ipv6)   labels.push(`${bt.ipv6} IPv6`);
  if (bt.domain) labels.push(`${bt.domain} Domain${bt.domain > 1 ? 's' : ''}`);
  if (bt.url)    labels.push(`${bt.url} URL${bt.url > 1 ? 's' : ''}`);
  if (bt.hash)   labels.push(`${bt.hash} Hash${bt.hash > 1 ? 'es' : ''}`);
  if (labels.length) parts.push(labels.join(' · '));
  const priv = filtered.filter(i => i.isPrivate).length;
  if (priv) parts.push(`<span style="color:var(--yellow)">${priv} private</span>`);

  if (info) info.innerHTML = parts.join(' · ');
  if (btn) btn.disabled = false;
}

function getInputText() { return document.getElementById('ioc-input')?.value || ''; }
