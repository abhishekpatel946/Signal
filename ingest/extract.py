"""Thin host-row extraction from a Shodan-style banner object."""

from __future__ import annotations

import re
from typing import Any

from ingest.config import (
    DANGEROUS_PORTS,
    DANGEROUS_PRODUCT_HINTS,
    DANGEROUS_RECORD_KEYS,
    MALWARE_MODULES,
    MAX_CVES_STORED,
    WAF_ALREADY_PROTECTED_HINTS,
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
CONTACT_URL_RE = re.compile(r"(?i)(?:contact|mailto):\s*(\S+)")


def _as_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if x]
    return [str(value)]


def _waf_name(http: dict | None) -> str | None:
    if not http:
        return None
    waf = http.get("waf")
    if not waf:
        return None
    return str(waf)[:80]


def _is_protected_waf(waf: str | None) -> bool:
    if not waf:
        return False
    low = waf.lower()
    return any(h in low for h in WAF_ALREADY_PROTECTED_HINTS)


def _security_contact(http: dict | None) -> str | None:
    if not http:
        return None
    txt = http.get("securitytxt")
    if not txt or not isinstance(txt, str):
        return None
    emails = EMAIL_RE.findall(txt)
    if emails:
        return emails[0].lower()
    for match in CONTACT_URL_RE.findall(txt):
        cleaned = match.strip().rstrip(",")
        if cleaned:
            return cleaned[:200]
    return None


def _vulns(rec: dict) -> list[dict]:
    raw = rec.get("vulns")
    if not isinstance(raw, dict):
        return []
    out = []
    for cve, meta in list(raw.items())[: MAX_CVES_STORED * 2]:
        if not isinstance(meta, dict):
            meta = {}
        out.append(
            {
                "id": str(cve)[:32],
                "cvss": float(meta.get("cvss") or 0),
                "epss": float(meta.get("epss") or 0),
            }
        )
    out.sort(key=lambda v: (v["cvss"], v["epss"]), reverse=True)
    return out[:MAX_CVES_STORED]


def _dangerous_reason(rec: dict, product: str | None, port: int | None) -> str | None:
    keys_hit = [k for k in DANGEROUS_RECORD_KEYS if rec.get(k)]
    if keys_hit:
        return keys_hit[0]
    prod = (product or "").lower()
    for hint in DANGEROUS_PRODUCT_HINTS:
        if hint in prod:
            return hint
    tags = {t.lower() for t in (rec.get("tags") or []) if isinstance(t, str)}
    if "database" in tags:
        return "database"
    if "iot" in tags:
        return "iot"
    if port in DANGEROUS_PORTS:
        return f"port-{port}"
    return None


def _iot(rec: dict, product: str | None, dangerous: str | None) -> bool:
    tags = {t.lower() for t in (rec.get("tags") or []) if isinstance(t, str)}
    if "iot" in tags:
        return True
    blob = f"{product or ''} {dangerous or ''} {rec.get('_shodan', {}).get('module') or ''}".lower()
    return any(x in blob for x in ("hikvision", "dahua", "camera", "dvr", "nvr", "webcam"))


def extract_host(rec: dict, batch_id: str) -> dict:
    http = rec.get("http") if isinstance(rec.get("http"), dict) else None
    ssl = rec.get("ssl") if isinstance(rec.get("ssl"), dict) else None
    loc = rec.get("location") if isinstance(rec.get("location"), dict) else {}
    shodan = rec.get("_shodan") if isinstance(rec.get("_shodan"), dict) else {}
    tags = [str(t) for t in (rec.get("tags") or []) if t]
    tagset = {t.lower() for t in tags}
    product = rec.get("product")
    product_s = str(product)[:80] if product else None
    port = rec.get("port")
    try:
        port_i = int(port) if port is not None else None
    except (TypeError, ValueError):
        port_i = None
    waf = _waf_name(http)
    vulns = _vulns(rec)
    dangerous = _dangerous_reason(rec, product_s, port_i)
    module = str(shodan.get("module") or "")[:40] or None

    cvss_max = max((v["cvss"] for v in vulns), default=0.0)
    epss_max = max((v["epss"] for v in vulns), default=0.0)

    return {
        "batch_id": batch_id,
        "ip_str": rec.get("ip_str") or rec.get("ipv6"),
        "port": port_i,
        "transport": rec.get("transport"),
        "timestamp": rec.get("timestamp"),
        "org": (rec.get("org") or None) and str(rec.get("org"))[:120],
        "isp": (rec.get("isp") or None) and str(rec.get("isp"))[:120],
        "asn": rec.get("asn"),
        "country": loc.get("country_code"),
        "city": loc.get("city"),
        "hostnames": _as_list(rec.get("hostnames"))[:8],
        "domains": _as_list(rec.get("domains"))[:8],
        "product": product_s,
        "version": (str(rec.get("version"))[:40] if rec.get("version") else None),
        "tags": tags[:16],
        "module": module,
        "has_http": bool(http),
        "has_ssl": bool(ssl),
        "waf": waf,
        "waf_protected": _is_protected_waf(waf),
        "security_contact": _security_contact(http),
        "vulns": vulns,
        "cvss_max": cvss_max,
        "epss_max": epss_max,
        "n_vulns": len(vulns),
        "eol": "eol-product" in tagset,
        "self_signed": "self-signed" in tagset,
        "is_honeypot": "honeypot" in tagset,
        "is_cdn": "cdn" in tagset,
        "is_cloud": "cloud" in tagset,
        "dangerous": dangerous,
        "is_iot": _iot(rec, product_s, dangerous),
        "is_malware_c2": bool(module and module.lower() in MALWARE_MODULES),
    }
