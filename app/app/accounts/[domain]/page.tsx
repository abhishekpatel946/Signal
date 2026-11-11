import { notFound } from "next/navigation";
import { getAccount, loadAccounts } from "@/lib/data";

function scoreClass(score: number) {
  if (score >= 55) return "hot";
  if (score >= 28) return "mid";
  return "ok";
}

export function generateStaticParams() {
  return loadAccounts()
    .slice(0, 400)
    .map((a) => ({ domain: a.domain }));
}

export default function AccountPage({ params }: { params: { domain: string } }) {
  const domain = decodeURIComponent(params.domain);
  const a = getAccount(domain);
  if (!a) notFound();

  return (
    <main className="wrap">
      <a className="back" href="/">
        ← Back to queue
      </a>
      <p style={{ color: "var(--muted)", fontSize: 13, letterSpacing: "0.06em", textTransform: "uppercase" }}>
        {a.country || "unknown geo"} · {a.n_ips} IPs · {a.n_hosts} services
      </p>
      <h1>{a.domain}</h1>
      <p className="lede">{a.why}</p>
      <div className="stats">
        <div className="stat">
          <b className={`score ${scoreClass(a.score)}`}>{a.score}</b>
          <span>need-now score</span>
        </div>
        <div className="stat">
          <b className={`decision ${a.decision}`}>{a.decision.replace("_", " ")}</b>
          <span>decision</span>
        </div>
        <div className="stat">
          <b>{a.cvss_max || "—"}</b>
          <span>max CVSS</span>
        </div>
        <div className="stat">
          <b>{a.security_contacts[0] || "none"}</b>
          <span>security.txt contact</span>
        </div>
      </div>

      <div className="grid2">
        <div className="card">
          <h2>Evidence a salesperson can use</h2>
          {a.evidence.length === 0 && <p className="lede">No banner-level evidence stored.</p>}
          {a.evidence.map((e, i) => (
            <div className="ev" key={i}>
              <span className={`pill ${e.kind === "cve" ? "cve" : e.kind === "exposure" ? "exposure" : e.kind === "eol" ? "eol" : ""}`}>
                {e.kind}
              </span>
              <div>{e.detail}</div>
              <div className="why mono">
                {e.ip}
                {e.port ? `:${e.port}` : ""} {e.product} {e.version} {e.country}
              </div>
            </div>
          ))}
        </div>
        <div>
          <div className="card" style={{ marginBottom: 12 }}>
            <h2>Why this score</h2>
            {a.reasons.map((r) => (
              <div className="ev" key={r}>
                {r}
              </div>
            ))}
            <div className="ev mono">
              {Object.entries(a.breakdown).map(([k, v]) => (
                <div key={k}>
                  {k}: +{v}
                </div>
              ))}
              <div>fit: {a.fit}</div>
            </div>
          </div>
          <div className="card">
            <h2>Footprint</h2>
            <div className="ev">Observed org (usually hoster): {a.org_observed || "—"}</div>
            <div className="ev">Products: {a.products.join(", ") || "—"}</div>
            <div className="ev">Dangerous services: {a.dangerous.join(", ") || "none"}</div>
            <div className="ev">City: {a.city || "—"}</div>
            <div className="ev">
              WAF already present: {a.signals.waf_present ? "yes (displacement)" : "no"}
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
