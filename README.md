# Signal — attack-surface sales intel

Take-home prototype for a **cybersecurity software** sales team: given a raw internet-wide scan, which **named companies** look like they need help *this week*, and why.

Live app: see the Vercel URL in the submission note (deployed from `app/`).

This is not a CRM dump and not an email writer. The source file is a **Zstandard JSONL Shodan-style banner feed** (~16.9 GB). Each line is an IP/port/service. The sales unit is a **company**. The work is entity resolution + explainable risk signals.

## How a rep uses it

1. Open the queue. Accounts are already ranked.
2. Filter by country, CVE / exposure / EOL / no WAF, or search a domain.
3. Open an account: evidence (IP, port, product, CVE), score breakdown, `security.txt` contact if the scan saw one.
4. Call the ones marked **call now**. Do not pitch CDNs, honeypots, or ISP reverse-DNS umbrellas — those never enter the queue.

## Approach

```
zstd JSONL scan
  → stream to chunked Parquet (one file = one monthly batch)
  → resolve registrable domain (not the hosting org)
  → drop CDN / honeypot / ISP PTR / provider aggregates
  → rule-based 0–100 score + evidence
  → app/data/accounts.json → Next.js on Vercel
```

**Ingest** (`python -m ingest.run`) never loads the 17 GB file into RAM. Production volume is “hundreds of files like this per month”: same job, new `--batch-id`.

**Entity resolution** is the actual problem. Shodan’s `org` field is usually the ISP (`OVH SAS`, `Google LLC`). We take hostnames, `tldextract` a registrable domain, and throw away reverse-DNS, cloud PTR, and telco umbrellas. No name → not in the queue.

**Signals (no LLM)**

| Signal | Why it matters to a cybersecurity seller |
| --- | --- |
| CVSS / EPSS on internet-facing software | Unpatched attack surface (we score the *worst* CVE, not every CPE ID Shodan attached) |
| `eol-product` | Cannot patch — a project, not a ticket |
| Exposed SMB / Redis / K8s / VNC / cameras / DBs | Breach path a CISO understands |
| Self-signed TLS | Weak hygiene |
| HTTP risk and no WAF | Greenfield vs Cloudflare/Fortinet already present (displacement, down-weighted) |
| `security.txt` | Reachability, not risk |

Score = capped urgency points × fit multiplier (0–100), with a stored reason list. `call_now` ≥ 55, `watch` ≥ 28.

## This batch (numbers)

From **800,000** scan records (~12 min to ingest at ~1,100 records/s). Full-file ingest is the same command without `--max-records`.

| Step | Count |
| --- | --- |
| Hosts read | 800,000 |
| Honeypots dropped | 13,424 |
| No usable company domain | 663,503 |
| Named domains aggregated | 41,053 |
| Exported to the sales queue (score ≥ 12) | 7,777 |
| Mean score, top 100 | 52.8 |
| Top 100 with at least one CVE | 99% |

`python -m ingest.score` is deterministic on a given Parquet batch.

## How we measured it

There are no conversion labels in the scan. We use proxy tests a reviewer can re-run:

```bash
python -m eval.sample_gold
python -m eval.metrics
```

Last run (`eval/metrics.json`):

- **Call rate @50 / @100:** 0.78 / 0.83 — production `auto_label` (named buyer with material risk, not a telco/hoster).
- **Call rate on all 7,777 exported accounts:** 0.084 — the ranker concentrates “call” accounts ~9× vs the exported set.
- **Noise leak in top 100:** 0 (no leftover CDN/cloud PTR suffixes).
- **High-severity finding:** 100% of the exported set, including a random 100. That is by design: we drop low-score rows before export. Ranking quality is *who to call*, not *whether a CVE exists*.
- **Gold sample:** 100 stratified rows (top / mid / tail) in `eval/gold.json`, hand-labeled. Agreement with `auto_label`: **0.82**. 14 of the hand `call` labels sit in the scored top 100.
- **Stability:** re-run `python -m ingest.score` on the same Parquet → same domain, score, and evidence class.

We did **not** use an LLM, so there is no token cost to report.

## Run it locally

Python 3.11+:

```bash
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
python -m ingest.run --input b2_download_file_by_id --max-records 800000
python -m ingest.score
python -m eval.sample_gold
python -m eval.metrics
```

App:

```bash
cd app
npm install
npm run dev
```

The 17 GB scan file is gitignored. Do not commit it. `app/data/accounts.json` is the only data the hosted app needs.

## Decisions we would defend in interview

1. **Spend time on signals, not UI or email.** The brief said so; the product is a ranked queue with evidence.
2. **Do not treat `org` as the customer.** That single mistake turns the demo into “rank every Apache at AWS”.
3. **Do not count every CVE ID.** Shodan attaches the full CPE list; counting them saturates the score at 100.
4. **ISP reverse-DNS is not pipeline.** `*.bsnl.co.in` across 14 customer IPs is a telco, not 14 buyers.
5. **Precompute for Vercel.** Ingest is a batch job. The web app ships a compact account table.

## Layout

- `ingest/` — stream, extract, resolve, score, export
- `app/` — Next.js App Router (queue, account, method)
- `eval/` — gold sample + metrics
- `data/parquet/` — local host chunks (gitignored)
