import { listMeta, loadAccounts } from "@/lib/data";
import Queue from "@/components/Queue";

export default function HomePage() {
  const accounts = loadAccounts().map((a) => ({
    domain: a.domain,
    score: a.score,
    decision: a.decision,
    why: a.why,
    country: a.country,
    org_observed: a.org_observed,
    n_hosts: a.n_hosts,
    cvss_max: a.cvss_max,
    fit: a.fit,
    icp: a.icp || "smb",
    breakdown: a.breakdown,
    signals: a.signals,
    security_contacts: a.security_contacts,
  }));
  const stats = listMeta();
  return (
    <main className="wrap">
      <p style={{ color: "var(--muted)", fontSize: 13, letterSpacing: "0.06em", textTransform: "uppercase" }}>
        Cybersecurity sales intelligence
      </p>
      <h1>Who needs help right now</h1>
      <p className="lede">
        Ranked from a Shodan-style internet scan. Each account is a named company domain, not
        an ISP or CDN. Score is explainable: CVEs, exposed admin/data services, end-of-life
        software, missing WAF — with the evidence a rep can say on a call.
      </p>
      <div className="stats">
        <div className="stat">
          <b>{accounts.length.toLocaleString()}</b>
          <span>named accounts in queue</span>
        </div>
        <div className="stat">
          <b>{(stats.hosts_read ?? 0).toLocaleString()}</b>
          <span>scan records ingested</span>
        </div>
        <div className="stat">
          <b>{(stats.pct_top100_cve ?? 0).toFixed(0)}%</b>
          <span>of top 100 have CVEs</span>
        </div>
        <div className="stat">
          <b>{(stats.mean_top100 ?? 0).toFixed(0)}</b>
          <span>mean score, top 100</span>
        </div>
      </div>
      <Queue accounts={accounts} />
    </main>
  );
}
