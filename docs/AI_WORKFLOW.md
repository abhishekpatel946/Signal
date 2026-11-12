# AI-native build loop (Firmable take-home)

Firmable asked how we work with AI, not only what we ship. **Runtime scoring stays deterministic**; agents accelerated exploration and iteration.

## 1. Data discovery (human + scripts, not “paste file into ChatGPT”)

- Streamed the ZSTD JSONL with small Python peeks (`eval/peek.py`, local) to confirm banner shape: `org` vs `hostnames`, `vulns`, `tags`, `http.securitytxt`.
- Conclusion captured in README: treating `org` as the customer collapses the product into “rank every Apache at AWS.”

## 2. Where Cursor / agents helped

| Area | Agent role | Human verification |
| --- | --- | --- |
| Parquet ingest boilerplate | chunked writers, argparse | Re-run on 800k rows; RAM flat |
| Next.js static export + pagination | UI wiring | Manual click-through on queue |
| Denylist expansion | Suggest PTR patterns from false positives | Re-score; `eval/metrics.py` precision@K |
| Docs alignment | README / ARCHITECTURE sync | Interview-defensible claims only |

## 3. What we did **not** trust an LLM with

- **Production labels or scores** — no API calls in `ingest/score.py`.
- **Entity resolution** — rules + `tldextract` + denylists; gold sample hand labels (`eval/hand_label.py`).

### LLM experiment we rejected (documented reasoning)

We considered LLM summarisation of `why` strings from evidence blobs. Rejected because:

- Cost scales with queue size (7k+ accounts × monthly batches).
- Non-deterministic output is hard for reps to defend on a call.
- Rule-based `reasons[]` already maps 1:1 to evidence rows.

If we revisited: A/B on 50 gold accounts, max token budget per account, agreement threshold ≥ 0.9 with hand labels.

## 4. How we know it works

```bash
python -m eval.sample_gold
python -m eval.metrics
```

Outputs: `eval/metrics.json`, `app/data/metrics.json` (shown on Method page). Metrics include precision@K, provider leak in top 100, and agreement with stratified hand labels — not proxy “high CVE rate” alone.

## 5. Month-over-month (production sketch)

`ingest/pipeline.py --batch-id YYYY-MM` writes a new Parquet folder. A second scoring pass can diff domain-level scores (not implemented in UI; architecture in ARCHITECTURE.md). Fresh banner timestamps already boost “reach them first” within a single batch.
