import { listMeta } from "@/lib/data";

export default function MethodPage() {
  const stats = listMeta();
  return (
    <main className="wrap method">
      <h1>How scoring works</h1>
      <p>
        The source file is a Zstandard JSONL internet scan (Shodan-style banners), not a CRM.
        We never treat the hosting <strong>org</strong> as the buyer. We resolve a registrable
        domain from hostnames, drop CDN/honeypot/ISP reverse-DNS, then roll services up to that
        company.
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
          <strong>security.txt</strong> is reachability, not risk — it tells the rep how to start.
        </li>
      </ul>
      <p>
        Score is 0–100 from those weights, times a fit multiplier. CDN-only and honeypot footprints
        are excluded. Accounts already behind Cloudflare/Fortinet/etc. are down-weighted as
        displacement, not mixed into “unprotected”.
      </p>
      <p>
        No LLM is used. Every point maps to a stored evidence row (IP, port, product, CVE).
      </p>
      <h2>This batch</h2>
      <ul>
        {Object.entries(stats).map(([k, v]) => (
          <li key={k}>
            <strong>{k}</strong>: {String(v)}
          </li>
        ))}
      </ul>
      <p>
        Measurement (precision@K, noise leak, high-severity rate vs random) lives in{" "}
        <code>eval/metrics.json</code> and the repository README.
      </p>
    </main>
  );
}
