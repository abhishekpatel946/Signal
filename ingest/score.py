"""Roll host Parquet up to scored companies and export compact JSON."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from ingest.config import (
    MAX_ACCOUNTS_EXPORT,
    MAX_EVIDENCE_PER_ACCOUNT,
    MIN_SCORE_EXPORT,
    WEIGHTS,
)
from ingest.resolve import (
    infer_icp_tag,
    is_isp_domain,
    is_isp_org,
    is_provider_domain,
    is_reseller_org,
    looks_like_infra_hostname,
    pick_company_domain,
)


def _empty_acc(domain: str) -> dict[str, Any]:
    return {
        "domain": domain,
        "orgs": Counter(),
        "countries": Counter(),
        "products": Counter(),
        "ips": set(),
        "n_hosts": 0,
        "n_http": 0,
        "n_ssl": 0,
        "n_cdn": 0,
        "n_cloud": 0,
        "n_honeypot": 0,
        "n_eol": 0,
        "n_self_signed": 0,
        "n_iot": 0,
        "n_malware": 0,
        "n_dangerous": 0,
        "n_waf_protected": 0,
        "n_http_no_waf": 0,
        "cvss_max": 0.0,
        "epss_max": 0.0,
        "n_vuln_hosts": 0,
        "cves": {},
        "dangerous_kinds": Counter(),
        "security_contacts": set(),
        "evidence": [],
        "cities": Counter(),
        "n_ptr_like": 0,
        "ts_max": None,
    }


def _add_evidence(acc: dict, host: dict, kind: str, detail: str) -> None:
    if len(acc["evidence"]) >= MAX_EVIDENCE_PER_ACCOUNT:
        return
    key = (kind, host.get("ip_str"), host.get("port"), detail[:80])
    if any(
        (e["kind"], e.get("ip"), e.get("port"), e.get("detail", "")[:80]) == key
        for e in acc["evidence"]
    ):
        return
    acc["evidence"].append(
        {
            "kind": kind,
            "detail": detail[:220],
            "ip": host.get("ip_str"),
            "port": host.get("port"),
            "product": host.get("product"),
            "version": host.get("version"),
            "country": host.get("country"),
        }
    )


def consume_host(acc: dict, host: dict) -> None:
    acc["n_hosts"] += 1
    if host.get("ip_str"):
        acc["ips"].add(host["ip_str"])
        if len(acc["ips"]) > 80:
            # keep cardinality cheap
            pass
    if host.get("org"):
        acc["orgs"][host["org"]] += 1
    if host.get("country"):
        acc["countries"][host["country"]] += 1
    if host.get("city"):
        acc["cities"][host["city"]] += 1
    if host.get("product"):
        acc["products"][host["product"]] += 1
    names = list(host.get("hostnames") or []) + list(host.get("domains") or [])
    if names and all(looks_like_infra_hostname(n) for n in names):
        acc["n_ptr_like"] += 1
    elif names and sum(1 for n in names if looks_like_infra_hostname(n)) >= max(1, len(names) // 2):
        acc["n_ptr_like"] += 1
    if host.get("has_http"):
        acc["n_http"] += 1
        if not host.get("waf_protected"):
            acc["n_http_no_waf"] += 1
    if host.get("has_ssl"):
        acc["n_ssl"] += 1
    if host.get("is_cdn"):
        acc["n_cdn"] += 1
    if host.get("is_cloud"):
        acc["n_cloud"] += 1
    if host.get("is_honeypot"):
        acc["n_honeypot"] += 1
    if host.get("eol"):
        acc["n_eol"] += 1
        _add_evidence(
            acc,
            host,
            "eol",
            f"End-of-life {host.get('product') or 'software'} {host.get('version') or ''}".strip(),
        )
    if host.get("self_signed"):
        acc["n_self_signed"] += 1
        _add_evidence(acc, host, "self_signed", "Self-signed TLS certificate on a public service")
    if host.get("is_iot"):
        acc["n_iot"] += 1
        _add_evidence(
            acc,
            host,
            "iot",
            f"IoT/camera-class device exposed ({host.get('product') or host.get('module') or 'iot'})",
        )
    if host.get("is_malware_c2"):
        acc["n_malware"] += 1
        _add_evidence(
            acc,
            host,
            "malware",
            f"Malware/C2 fingerprint on this IP (module={host.get('module')})",
        )
    if host.get("dangerous"):
        acc["n_dangerous"] += 1
        acc["dangerous_kinds"][host["dangerous"]] += 1
        _add_evidence(
            acc,
            host,
            "exposure",
            f"Internet-exposed {host['dangerous']} (port {host.get('port')})",
        )
    if host.get("waf_protected"):
        acc["n_waf_protected"] += 1
    if host.get("security_contact"):
        acc["security_contacts"].add(host["security_contact"])
    ts = host.get("timestamp")
    if isinstance(ts, (int, float)) and ts > 1_000_000_000:
        prev = acc["ts_max"]
        acc["ts_max"] = max(prev or 0, int(ts))

    vulns = host.get("vulns") or []
    if vulns:
        acc["n_vuln_hosts"] += 1
        acc["cvss_max"] = max(acc["cvss_max"], float(host.get("cvss_max") or 0))
        acc["epss_max"] = max(acc["epss_max"], float(host.get("epss_max") or 0))
        top = sorted(vulns, key=lambda v: float(v.get("cvss") or 0), reverse=True)[:4]
        for v in top:
            cid = v.get("id")
            if not cid:
                continue
            prev = acc["cves"].get(cid)
            cvss = float(v.get("cvss") or 0)
            epss = float(v.get("epss") or 0)
            if not prev or cvss > prev["cvss"]:
                acc["cves"][cid] = {"id": cid, "cvss": cvss, "epss": epss}
        best = top[0]
        _add_evidence(
            acc,
            host,
            "cve",
            f"{best.get('id')} CVSS {best.get('cvss')} on {host.get('product') or 'service'} {host.get('version') or ''}".strip(),
        )


def fit_multiplier(acc: dict, domain: str) -> tuple[float, str]:
    """0 = drop from queue. CDN-only / honeypot-only assets are not ICP."""
    n_ips = min(len(acc["ips"]), 80)
    top_org = acc["orgs"].most_common(1)[0][0] if acc["orgs"] else None
    if is_provider_domain(domain):
        return 0.0, "hosting_provider"
    if is_reseller_org(top_org):
        return 0.0, "reseller_org"
    if top_org and any(
        x in (top_org or "").lower()
        for x in (
            "chinanet",
            "china telecom",
            "china unicom",
            "china mobile",
            "railtel",
            "telefonica",
            "magyar telekom",
            "orange polska",
            "telmex",
            "comcast cable",
            "unified layer",
            "rackspace",
            "gmo internet",
        )
    ):
        return 0.0, "telco_footprint"
    if acc["n_honeypot"] and acc["n_honeypot"] >= acc["n_hosts"] * 0.8:
        return 0.0, "honeypot"
    if acc["n_cdn"] and acc["n_cdn"] >= acc["n_hosts"] * 0.9 and acc["n_dangerous"] == 0 and acc["n_vuln_hosts"] == 0:
        return 0.0, "cdn_only"
    if is_isp_domain(domain):
        return 0.0, "isp_domain"
    # Reverse-DNS umbrellas (dynamic.isp.tld across many customer IPs) are not buyers.
    if acc["n_hosts"] >= 3 and acc["n_ptr_like"] / acc["n_hosts"] >= 0.5 and n_ips >= 3:
        return 0.0, "ptr_umbrella"
    if n_ips >= 20 or acc["n_hosts"] >= 50:
        return 0.0, "provider_aggregate"
    if domain in {"google.com", "cloudflare.com", "amazon.com", "microsoft.com"}:
        return 0.0, "hyperscaler"
    ispish = is_isp_org(top_org)
    if ispish and acc["n_hosts"] == 1 and not acc["n_vuln_hosts"] and not acc["n_dangerous"] and not acc["n_eol"]:
        return 0.15, "single_hosted_no_risk"
    if ispish:
        return 0.85, "hosted_named_domain"
    return 1.0, "named_business"


def compute_score(acc: dict, domain: str, batch_ts_max: int | None = None) -> dict:
    fit, fit_reason = fit_multiplier(acc, domain)
    if fit <= 0:
        return {"score": 0, "fit": fit_reason, "urgency": 0, "breakdown": {}, "reasons": []}

    breakdown: dict[str, int] = {}
    reasons: list[str] = []

    crit = sum(1 for c in acc["cves"].values() if c["cvss"] >= 9)
    high = sum(1 for c in acc["cves"].values() if 7 <= c["cvss"] < 9)
    med = sum(1 for c in acc["cves"].values() if 4 <= c["cvss"] < 7)
    # Count severity bands, not every CPE-mapped CVE (Shodan dumps the full list per product).
    if acc["cvss_max"] >= 9:
        breakdown["critical_cve"] = WEIGHTS["critical_cve"]
        reasons.append(
            f"Critical internet-facing CVE (CVSS {acc['cvss_max']:.1f}"
            + (f", {crit} listed)" if crit else ")")
        )
    elif acc["cvss_max"] >= 7:
        breakdown["high_cve"] = WEIGHTS["high_cve"]
        reasons.append(f"High CVE on a public service (CVSS {acc['cvss_max']:.1f}, {high} listed)")
    elif acc["cvss_max"] >= 4:
        breakdown["medium_cve"] = WEIGHTS["medium_cve"]
    if acc["epss_max"] >= 0.5:
        breakdown["high_epss"] = WEIGHTS["high_epss"]
        reasons.append(f"High exploit probability (EPSS {acc['epss_max']:.2f})")
    elif acc["epss_max"] >= 0.2:
        breakdown["high_epss"] = WEIGHTS["high_epss"] // 2
        reasons.append(f"Elevated exploit probability (EPSS {acc['epss_max']:.2f})")
    if acc["n_vuln_hosts"] >= 3:
        breakdown["cve_breadth"] = WEIGHTS["cve_breadth"]
        reasons.append(f"Unpatched software on {acc['n_vuln_hosts']} distinct services")
    if acc["n_eol"]:
        breakdown["eol"] = WEIGHTS["eol"]
        reasons.append(f"End-of-life software on {acc['n_eol']} service(s)")
    if acc["n_dangerous"]:
        kinds = ", ".join(k for k, _ in acc["dangerous_kinds"].most_common(3))
        breakdown["dangerous_exposure"] = min(28, WEIGHTS["dangerous_exposure"] + min(8, acc["n_dangerous"]))
        reasons.append(f"Dangerous service(s) exposed: {kinds}")
    if acc["n_iot"]:
        breakdown["iot_camera"] = WEIGHTS["iot_camera"]
        reasons.append("IoT/camera gear reachable from the public internet")
    if acc["n_self_signed"]:
        breakdown["self_signed"] = WEIGHTS["self_signed"]
        reasons.append("Self-signed TLS on a public service")
    if acc["n_malware"]:
        breakdown["malware_c2"] = WEIGHTS["malware_c2"]
        reasons.append("Malware/C2 fingerprint on an asset in this footprint")
    if acc["n_http"] and acc["n_http_no_waf"] >= acc["n_http"] * 0.7 and (
        acc["n_vuln_hosts"] or acc["n_dangerous"] or acc["n_eol"]
    ):
        breakdown["no_waf_on_http"] = WEIGHTS["no_waf_on_http"]
        reasons.append("HTTP services with no WAF in front of known risk")
    if acc["n_http"] and not acc["security_contacts"] and (acc["n_vuln_hosts"] or acc["n_dangerous"]):
        breakdown["missing_securitytxt"] = WEIGHTS["missing_securitytxt"]
    if acc["security_contacts"]:
        breakdown["has_securitytxt_contact"] = WEIGHTS["has_securitytxt_contact"]
        reasons.append("security.txt lists a contact — reachable this week")
    ref = batch_ts_max or acc.get("ts_max")
    if ref and acc.get("ts_max") and (ref - acc["ts_max"]) <= 14 * 86400:
        breakdown["fresh_exposure"] = WEIGHTS["fresh_exposure"]
        reasons.append("Fresh internet exposure in the last ~2 weeks — reach them first")

    urgency = sum(breakdown.values())
    # Light penalty when the whole footprint is CDN/WAF already
    if acc["n_waf_protected"] and acc["n_waf_protected"] >= acc["n_http"] * 0.8 and acc["n_http"] >= 2:
        urgency = int(urgency * 0.72)
        reasons.append("Already behind a commercial WAF — displacement, not greenfield")

    raw = urgency * fit
    score = int(max(0, min(100, round(raw))))
    if not reasons and score > 0:
        reasons.append("Internet-facing software with weak hygiene")
    return {
        "score": score,
        "fit": fit_reason,
        "urgency": int(urgency),
        "breakdown": breakdown,
        "reasons": reasons[:6],
    }


def serialize(acc: dict, scored: dict) -> dict:
    top_org = acc["orgs"].most_common(1)[0][0] if acc["orgs"] else None
    country = acc["countries"].most_common(1)[0][0] if acc["countries"] else None
    city = acc["cities"].most_common(1)[0][0] if acc["cities"] else None
    cves = sorted(acc["cves"].values(), key=lambda c: c["cvss"], reverse=True)[:8]
    contacts = sorted(acc["security_contacts"])[:4]
    products = [p for p, _ in acc["products"].most_common(6)]
    buyer_fit = scored["fit"] in {"named_business", "hosted_named_domain"}
    decision = (
        "call_now"
        if buyer_fit and scored["score"] >= 55
        else "watch"
        if buyer_fit and scored["score"] >= 28
        else "low"
    )
    why = "; ".join(scored["reasons"]) if scored["reasons"] else "Limited public risk evidence."
    return {
        "domain": acc["domain"],
        "score": scored["score"],
        "decision": decision,
        "why": why,
        "fit": scored["fit"],
        "urgency": scored["urgency"],
        "breakdown": scored["breakdown"],
        "reasons": scored["reasons"],
        "country": country,
        "city": city,
        "org_observed": top_org,
        "n_hosts": acc["n_hosts"],
        "n_ips": min(len(acc["ips"]), 80),
        "n_http": acc["n_http"],
        "signals": {
            "cve": acc["n_vuln_hosts"] > 0,
            "exposure": acc["n_dangerous"] > 0,
            "eol": acc["n_eol"] > 0,
            "no_waf": acc["n_http"] > 0 and acc["n_http_no_waf"] >= acc["n_http"] * 0.7,
            "self_signed": acc["n_self_signed"] > 0,
            "iot": acc["n_iot"] > 0,
            "waf_present": acc["n_waf_protected"] > 0,
            "reachable": bool(contacts),
        },
        "cvss_max": round(acc["cvss_max"], 1),
        "epss_max": round(acc["epss_max"], 4),
        "cves": cves,
        "products": products,
        "dangerous": [k for k, _ in acc["dangerous_kinds"].most_common(5)],
        "security_contacts": contacts,
        "evidence": acc["evidence"],
        "icp": infer_icp_tag(acc["domain"], acc["n_hosts"]),
    }


def score_parquet(parquet_dir: Path) -> tuple[list[dict], dict]:
    files = sorted(parquet_dir.glob("hosts_*.parquet"))
    if not files:
        raise SystemExit(f"no parquet in {parquet_dir}")
    accounts: dict[str, dict] = {}
    n_hosts = 0
    n_named = 0
    n_skipped_no_domain = 0
    n_skipped_honeypot = 0

    for path in files:
        table = pq.read_table(path)
        for host in table.to_pylist():
            n_hosts += 1
            if host.get("is_honeypot"):
                n_skipped_honeypot += 1
                continue
            domain = pick_company_domain(host.get("hostnames") or [], host.get("domains") or [])
            if not domain:
                n_skipped_no_domain += 1
                continue
            n_named += 1
            if domain not in accounts:
                accounts[domain] = _empty_acc(domain)
            consume_host(accounts[domain], host)
        print(f"scored through {path.name} ({n_hosts:,} hosts, {len(accounts):,} domains)", flush=True)

    batch_ts_max = max((a.get("ts_max") or 0 for a in accounts.values()), default=0) or None

    exported: list[dict] = []
    dropped_fit = 0
    for domain, acc in accounts.items():
        scored = compute_score(acc, domain, batch_ts_max)
        if scored["score"] < MIN_SCORE_EXPORT:
            dropped_fit += 1
            continue
        exported.append(serialize(acc, scored))
    exported.sort(key=lambda a: (-a["score"], -a["cvss_max"], a["domain"]))
    exported = exported[:MAX_ACCOUNTS_EXPORT]

    stats = {
        "hosts_read": n_hosts,
        "hosts_named_domain": n_named,
        "skipped_no_domain": n_skipped_no_domain,
        "skipped_honeypot": n_skipped_honeypot,
        "companies_aggregated": len(accounts),
        "dropped_low_score": dropped_fit,
        "exported": len(exported),
        "mean_top100": round(sum(a["score"] for a in exported[:100]) / max(1, min(100, len(exported))), 1),
        "pct_top100_cve": round(
            100 * sum(1 for a in exported[:100] if a["signals"]["cve"]) / max(1, min(100, len(exported))),
            1,
        ),
    }
    return exported, stats


def write_outputs(exported: list[dict], stats: dict, out_json: Path, stats_path: Path) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_from": "Shodan-style internet scan (zstd JSONL)",
        "batch_id": None,
        "stats": stats,
        "accounts": exported,
    }
    out_json.write_text(json.dumps(payload, separators=(",", ":")))
    stats_path.write_text(json.dumps(stats, indent=2))
    print("export", stats)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parquet", default="data/parquet")
    parser.add_argument("--out", default="app/data/accounts.json")
    parser.add_argument("--stats", default="data/score_stats.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    parquet_dir = Path(args.parquet)
    if not parquet_dir.is_absolute():
        parquet_dir = root / parquet_dir
    out_json = Path(args.out)
    if not out_json.is_absolute():
        out_json = root / out_json
    stats_path = Path(args.stats)
    if not stats_path.is_absolute():
        stats_path = root / stats_path
    exported, stats = score_parquet(parquet_dir)
    write_outputs(exported, stats, out_json, stats_path)


if __name__ == "__main__":
    main()
