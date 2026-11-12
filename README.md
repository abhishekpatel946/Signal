# Signal — attack-surface sales intel

Take-home prototype for a **cybersecurity software** sales team: given a raw internet-wide scan, which **named companies** look like they need help *this week*, and why.

**Live app:** _(add your Vercel production URL after deploy — root directory `app/`)_

This is not a CRM dump and not an email writer. The source file is a **Zstandard JSONL Shodan-style banner feed** (~16.9 GB uncompressed stream). Each line is an IP/port/service. The sales unit is a **company**. The work is entity resolution + explainable risk signals.

Deeper design: **[ARCHITECTURE.md](./ARCHITECTURE.md)** (data flow, modules, scoring, what to commit).

## How a rep uses it

1. Open the queue. Accounts are already ranked.
2. Filter by country, **ICP** (edu / gov / enterprise / SMB), CVE / exposure / EOL / no WAF, or search a domain.
3. Open an account: evidence (IP, port, product, CVE), score breakdown, `security.txt` contact if the scan saw one.
4. **Export CSV** for the filtered list. Call the ones marked **call now** (buyer `fit` only — hosters never export).

## Approach

```
zstd JSONL scan
  → stream to chunked Parquet (one file = one monthly batch)
  → resolve registrable domain (not the hosting org)
  → drop CDN / honeypot / ISP PTR / provider aggregates
  → rule-based 0–100 score + evidence
  → app/data/accounts.json → Next.js static export on Vercel
```

**Ingest** (`python -m ingest.run`) never loads the full dump into RAM. Production volume is “hundreds of files like this per month”: same job, new `--batch-id` (see ARCHITECTURE).

**Entity resolution** is the actual problem. Shodan’s `org` field is usually the ISP (`OVH SAS`, `Google LLC`). We take hostnames, `tldextract` a registrable domain, and throw away reverse-DNS, cloud PTR, and telco umbrellas. No name → not in the queue.

**Signals (no LLM in the product)**

| Signal | Why it matters to a cybersecurity seller |
| --- | --- |
| CVSS / EPSS on internet-facing software | Unpatched attack surface (we score the *worst* CVE, not every CPE ID Shodan attached) |
| `eol-product` | Cannot patch — a project, not a ticket |
| Exposed SMB / Redis / K8s / VNC / cameras / DBs | Breach path a CISO understands |
| Self-signed TLS | Weak hygiene |
| HTTP risk and no WAF | Greenfield vs Cloudflare/Fortinet already present (displacement, down-weighted) |
| `security.txt` | Reachability, not risk |
| Fresh banner timestamp | “Reach them first” within ~2 weeks of batch peak |

Score = capped urgency points × fit multiplier (0–100), with a stored reason list. **Hoster/reseller domains and orgs are fit = 0** (never exported). `call_now` ≥ 55 on buyer fit, `watch` ≥ 28.

## This batch (numbers)

From **800,000** scan records (~12 min to ingest at ~1,100 records/s). **Full-file ingest** uses the same commands without `--max-records`; at the same throughput, the full ~16.9 GB stream is on the order of **4–5 hours** on a typical laptop (I/O bound; RAM stays flat via streaming). Each additional monthly file is `python -m ingest.pipeline --batch-id YYYY-MM`.

| Step | Count |
| --- | --- |
| Hosts read | 800,000 |
| Honeypots dropped | 13,424 |
| No usable company domain | 663,503 |
| Named domains aggregated | 41,053 |
| Exported to the sales queue (score ≥ 12) | 7,427 |
| Mean score, top 100 | 49.5 |
| Top 100 with at least one CVE | 99% |

`python -m ingest.score` is deterministic on a given Parquet batch.

## How we measured it

There are no conversion labels in the scan. We use proxy tests a reviewer can re-run:

```bash
python -m eval.sample_gold
python -m eval.metrics
```

Last run (`eval/metrics.json`):

- **Call rate @50 / @100:** 1.00 / 0.96 — production `auto_label` (named buyer with material risk, not a telco/hoster).
- **Call rate on all ~7.4k exported accounts:** ~0.081 — the ranker concentrates “call” accounts ~9× vs the exported set.
- **Noise leak in top 100:** 0 (no leftover CDN/cloud PTR suffixes).
- **Provider/hoster leak in top 100:** 0 — `is_provider_domain`, reseller-org, and telco footprint gates.
- **High-severity finding:** 100% of the exported set, including a random 100. That is by design: we drop low-score rows before export. Ranking quality is *who to call*, not *whether a CVE exists*.
- **Gold sample:** 100 stratified rows (top / mid / tail) in `eval/gold.json`, hand-labeled via `eval/hand_label.py`. Agreement with `auto_label`: **~0.94** (re-run after queue tightening). Few hand-`call` gold rows appear in the global top 100 because the gold set deliberately samples mid/tail ranks — not because the ranker misses obvious calls.
- **Stability:** re-run `python -m ingest.score` on the same Parquet → same domain, score, and evidence class.

We did **not** use an LLM in scoring (deterministic rules, no token cost). Evaluation is rule-based + hand-reviewed gold.

## How we built it (AI-assisted workflow)

See **[docs/AI_WORKFLOW.md](./docs/AI_WORKFLOW.md)** — data peeks, what agents helped with, what we refused to automate, and an LLM summarisation path we rejected with reasoning.

Product logic stays auditable Python; agents accelerated the dev loop.

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

Deploy (static export):

```bash
cd app
npm run build
npx vercel --prod
```

Set Vercel **Root Directory** to `app` when importing from GitHub.

## Repository layout & git hygiene

`.gitignore` keeps pushes limited to **working source + scored queue**:

| In git | Ignored (regenerate locally) |
| --- | --- |
| `ingest/`, `eval/`, `requirements.txt` | Raw scan file, `*.zst`, `*.parquet` |
| `app/` source + `app/data/accounts.json`, `app/data/metrics.json` | `app/node_modules/`, `.next/`, `out/`, `.vercel/` |
| `data/score_stats.json`, `eval/gold.json`, `eval/metrics.json` | `data/parquet/`, `.venv/`, `assets/`, secrets |
| `docs/AI_WORKFLOW.md`, `SUBMISSION_EMAIL.md` | Local scan file |

Do not commit the multi-GB scan. `app/data/accounts.json` is the precomputed payload the hosted app needs (~9 MB).

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
- `ARCHITECTURE.md` — system design and commit policy
- `docs/AI_WORKFLOW.md` — AI-native dev loop
- `SUBMISSION_EMAIL.md` — email template for Firmable
