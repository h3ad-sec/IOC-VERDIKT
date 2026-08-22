# IOC-VERDIKT

Bring-your-own-key IOC intelligence checker. Sub-tool under **H3AD-X** in the [H3AD-SEC](https://h3ad-sec.github.io) portfolio.

**No More Tool-Hopping.** No managed mode, no server-held API keys. Every scan runs against the keys you supply, stored only in your browser's `localStorage`.

## What it does

Paste or upload IOCs (IPs, domains, URLs, file hashes) in bulk and check them against 10 threat intelligence sources. Each source shows a simple per-row status badge (hit / clean / error / skipped / no key), with a formatted per-source breakdown available in a detail modal. There is no scoring engine or aggregate verdict by design; this tool surfaces raw source data, not a synthesized risk score. Results can be exported as CSV, JSON, Markdown, TXT, or Excel.

## IOC types (v1)

- IP (IPv4 + IPv6)
- Domain
- URL
- Hash (MD5 / SHA1 / SHA256 / SHA512)

## Sources and call paths

| Source | IOC types | Call path |
|---|---|---|
| VirusTotal | IP, Domain, URL, Hash | via relay |
| AbuseIPDB | IP | via relay |
| AlienVault OTX | IP, Domain, URL, Hash | direct from browser |
| ThreatFox | IP, Domain, Hash | via relay |
| IPLocate | IP | direct from browser |
| URLScan | Domain, URL | direct from browser |
| URLhaus | URL | via relay |
| MalwareBazaar | Hash | via relay |
| HybridAnalysis | Hash (MD5/SHA1/SHA256) | via relay |
| FileScan.io | Hash | via relay |

**Direct sources** (OTX, URLScan, IPLocate) have open CORS and are called straight from the browser with your key attached the way each vendor documents, no backend involved.

**Relay sources** go through a stateless `/api/{vendor}` passthrough on Vercel. Your key is sent as the `x-user-key` request header on every call and is forwarded to the vendor server-side. It is never logged or stored, and never sent as a query parameter.

## Stack

Vanilla HTML/CSS/JS, no framework, no build step. SheetJS (`xlsx`) for `.xlsx` file-upload parsing. Vercel serverless functions for the relay endpoints in `api/`.

## Local dev

Open `index.html` directly, or serve the folder with any static file server. Add your API keys in the SOURCE KEYS panel, click SAVE KEYS, then paste IOCs and analyze.
