import { listMeta, loadMetrics } from "@/lib/data";

export default function MethodPage() {
  const stats = listMeta();
  const metrics = loadMetrics();
  return (
    <main className="wrap method">
      <h1>How scoring works</h1>
      <p>
        The source file is a Zstandard JSONL internet scan (Shodan-style banners), not a CRM.
        We never treat the hosting <strong>org</strong> as the buyer. We resolve a registrable
        domain from hostnames, drop CDN/honeypot/ISP reverse-DNS and <strong>hosting-provider domains</strong>,
        then roll services up to that company.
      </p>
      <h2>Signals that mean “needs cybersecurity help”</h2>
      <ul>
        <li>
          <strong>Known CVEs</strong> on internet-facing software, weighted by CVSS and EPSS.
        </li>
        <li>
          <strong>End-of-life products</strong> (cannot be patched — a project, not a ticket).
        </li>
        <li>
          <strong>Dangerous exposures</strong>: SMB, Redis, MySQL, Kubernetes, VNC, Telnet, MQTT,
          cameras/DVRs, open databases.
        </li>
        <li>
          <strong>Self-signed TLS</strong> and HTTP with risk and no WAF.
        </li>
        <li>
          <strong>Fresh exposure</strong> (banner timestamp within ~2 weeks of batch max) — prioritise
          accounts you can reach first.
        </li>
        <li>
          <strong>security.txt</strong> is reachability, not risk — it tells the rep how to start.
        </li>
      </ul>
      <p>
        Score is 0–100 from those weights, times a fit multiplier. CDN-only and honeypot footprints
        are excluded. Reseller org strings (“Private Customer”, CHINANET) and hoster domains (e.g.{" "}
        <code>*.cloud</code> VPS brands) never enter the queue. Accounts already behind
        Cloudflare/Fortinet/etc. are down-weighted as displacement, not greenfield.
      </p>
      <p>
        Scoring is <strong>deterministic Python</strong> (no LLM at runtime). Every point maps to stored
        evidence (IP, port, product, CVE). LLMs were used only in the build loop — see{" "}
        <code>docs/AI_WORKFLOW.md</code>.
      </p>
      <h2>Queue quality (this batch)</h2>
      {metrics ? (
        <ul>
          <li>
            <strong>Precision @50 / @100</strong> (auto-label “would call”):{" "}
            {(metrics.precision_at_50 * 100).toFixed(0)}% / {(metrics.precision_at_100 * 100).toFixed(0)}%
          </li>
          <li>
            <strong>Provider/noise leak in top 100</strong>:{" "}
            {(metrics.provider_leak_top100 * 100).toFixed(0)}% (target ~0%)
          </li>
          <li>
            <strong>Gold hand-label agreement</strong>:{" "}
            {metrics.gold_auto_agreement != null
              ? `${(metrics.gold_auto_agreement * 100).toFixed(0)}% on ${metrics.gold_n} stratified rows`
              : "—"}
          </li>
          <li>
            <strong>High-severity in top 100</strong>: by design near 100% — export floor requires
            material risk; ranking quality is <em>who to call</em>, not whether a CVE exists.
          </li>
        </ul>
      ) : (
        <p className="lede">Run <code>python -m eval.metrics</code> to refresh metrics.json.</p>
      )}
      <h2>This batch</h2>
      <ul>
        {Object.entries(stats).map(([k, v]) => (
          <li key={k}>
            <strong>{k}</strong>: {String(v)}
          </li>
        ))}
      </ul>
      <p>
        Full-file ingest: omit <code>--max-records</code> (~1,100 records/s observed; expect on the
        order of hours for the full ~17 GB stream). Each new monthly file is another{" "}
        <code>--batch-id</code> under <code>data/parquet/</code>.
      </p>
    </main>
  );
}
