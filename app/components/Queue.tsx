"use client";

import { useEffect, useMemo, useState } from "react";

const PAGE_SIZE = 50;

type Row = {
  domain: string;
  score: number;
  decision: "call_now" | "watch" | "low";
  why: string;
  country: string | null;
  org_observed: string | null;
  n_hosts: number;
  cvss_max: number;
  signals: {
    cve: boolean;
    exposure: boolean;
    eol: boolean;
    no_waf: boolean;
    self_signed: boolean;
    iot: boolean;
    waf_present: boolean;
    reachable: boolean;
  };
  security_contacts: string[];
};

const SIGNAL_FILTERS = [
  { id: "cve", label: "CVE" },
  { id: "exposure", label: "Exposure" },
  { id: "eol", label: "EOL" },
  { id: "no_waf", label: "No WAF" },
  { id: "iot", label: "IoT" },
  { id: "reachable", label: "Has contact" },
] as const;

function scoreClass(score: number) {
  if (score >= 55) return "hot";
  if (score >= 28) return "mid";
  return "ok";
}

export default function Queue({ accounts }: { accounts: Row[] }) {
  const [q, setQ] = useState("");
  const [country, setCountry] = useState("all");
  const [decision, setDecision] = useState<"all" | Row["decision"]>("all");
  const [minScore, setMinScore] = useState(12);
  const [signals, setSignals] = useState<string[]>([]);
  const [page, setPage] = useState(1);

  const countries = useMemo(() => {
    const set = new Set<string>();
    for (const a of accounts) if (a.country) set.add(a.country);
    return ["all", ...Array.from(set).sort()];
  }, [accounts]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return accounts.filter((a) => {
      if (a.score < minScore) return false;
      if (country !== "all" && a.country !== country) return false;
      if (decision !== "all" && a.decision !== decision) return false;
      if (needle && !a.domain.includes(needle) && !(a.org_observed || "").toLowerCase().includes(needle)) {
        return false;
      }
      for (const s of signals) {
        if (!(a.signals as Record<string, boolean>)[s]) return false;
      }
      return true;
    });
  }, [accounts, q, country, decision, minScore, signals]);

  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);

  useEffect(() => {
    setPage(1);
  }, [q, country, decision, minScore, signals]);

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const pageRows = useMemo(() => {
    const start = (safePage - 1) * PAGE_SIZE;
    return rows.slice(start, start + PAGE_SIZE);
  }, [rows, safePage]);

  const rangeStart = rows.length === 0 ? 0 : (safePage - 1) * PAGE_SIZE + 1;
  const rangeEnd = Math.min(safePage * PAGE_SIZE, rows.length);

  function toggle(id: string) {
    setSignals((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }

  return (
    <div>
      <div className="filters">
        <input
          placeholder="Search domain or observed org"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <select value={country} onChange={(e) => setCountry(e.target.value)}>
          {countries.map((c) => (
            <option key={c} value={c}>
              {c === "all" ? "All countries" : c}
            </option>
          ))}
        </select>
        <select value={minScore} onChange={(e) => setMinScore(Number(e.target.value))}>
          <option value={12}>Score ≥ 12</option>
          <option value={28}>Score ≥ 28 (watch)</option>
          <option value={55}>Score ≥ 55 (call now)</option>
        </select>
        <select value={decision} onChange={(e) => setDecision(e.target.value as typeof decision)}>
          <option value="all">All decisions</option>
          <option value="call_now">Call now</option>
          <option value="watch">Watch</option>
          <option value="low">Low</option>
        </select>
        <div className="chips">
          {SIGNAL_FILTERS.map((f) => (
            <button
              key={f.id}
              className={signals.includes(f.id) ? "chip on" : "chip"}
              onClick={() => toggle(f.id)}
              type="button"
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>
      <p className="lede" style={{ marginTop: 0 }}>
        {rows.length === 0
          ? `No accounts match — ${accounts.length.toLocaleString()} total in queue`
          : `Showing ${rangeStart.toLocaleString()}–${rangeEnd.toLocaleString()} of ${rows.length.toLocaleString()} matches (${accounts.length.toLocaleString()} total)`}
      </p>
      <table>
        <thead>
          <tr>
            <th>Score</th>
            <th>Account</th>
            <th>Signals</th>
            <th>Geo</th>
            <th>Decision</th>
          </tr>
        </thead>
        <tbody>
          {pageRows.map((a) => (
            <tr key={a.domain}>
              <td className={`score ${scoreClass(a.score)}`}>{a.score}</td>
              <td>
                <a className="domain" href={`/accounts/${encodeURIComponent(a.domain)}`}>
                  {a.domain}
                </a>
                <div className="why">{a.why}</div>
              </td>
              <td>
                {a.signals.cve && <span className="pill cve">CVE {a.cvss_max || ""}</span>}
                {a.signals.exposure && <span className="pill exposure">exposure</span>}
                {a.signals.eol && <span className="pill eol">EOL</span>}
                {a.signals.no_waf && <span className="pill">no WAF</span>}
                {a.signals.iot && <span className="pill">IoT</span>}
                {a.signals.reachable && <span className="pill">contact</span>}
              </td>
              <td className="mono">
                {a.country || "—"}
                <div className="why">{a.n_hosts} services</div>
              </td>
              <td className={`decision ${a.decision}`}>{a.decision.replace("_", " ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > PAGE_SIZE && (
        <nav className="pagination" aria-label="Account list pages">
          <button
            type="button"
            className="page-btn"
            disabled={safePage <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Previous
          </button>
          <span className="page-meta">
            Page {safePage} of {totalPages}
          </span>
          <button
            type="button"
            className="page-btn"
            disabled={safePage >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            Next
          </button>
        </nav>
      )}
    </div>
  );
}
