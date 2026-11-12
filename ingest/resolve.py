"""Map hostnames to a buyer company (registrable domain), not the hosting ISP."""

from __future__ import annotations

import re
from functools import lru_cache

import tldextract

from ingest.config import (
    HOSTING_REGISTRABLE,
    TELCO_REGISTRABLE,
    ISP_DOMAIN_SUFFIXES,
    ISP_ORG_SUBSTRINGS,
    JUNK_DOMAIN_SUFFIXES,
    JUNK_REGISTRABLE,
    PROVIDER_DOMAIN_SUBSTRINGS,
    PROVIDER_DOMAIN_TOKENS,
    RESELLER_ORG_PHRASES,
)

_extract = tldextract.TLDExtract(suffix_list_urls=())

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HEX_LABEL_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)
VPS_LABEL_RE = re.compile(
    r"(?:^|\.)(?:vps|host|server|ns\d*|mail\d*|web\d*|cdn\d*|static|dyn|dynamic|ip|ptr|rev|reverse)(?:-|\.|$)",
    re.I,
)
NUMERIC_HOST_RE = re.compile(
    r"(?:\d{1,3}-){3}\d{1,3}|(?:\d{1,3}\.){3}\d{1,3}|ip-\d+|ec2-\d+|host-\d+|user-\d+",
    re.I,
)
PTR_HINT_RE = re.compile(
    r"(?:^|\.|-)(?:dynamic|static|adsl|pppoe|dhcp|broadband|dialup|dial-up|pool|cust|customer|dsl|cablemodem|ftth|fttx|residencial|reverse|ptr)(?:-|\.|$)",
    re.I,
)


def is_junk_suffix(domain: str) -> bool:
    d = domain.lower().strip(".")
    for suffix in JUNK_DOMAIN_SUFFIXES:
        if d == suffix or d.endswith("." + suffix):
            return True
    return False


def is_isp_org(org: str | None) -> bool:
    if not org:
        return True
    low = org.lower()
    return any(s in low for s in ISP_ORG_SUBSTRINGS)


def looks_like_infra_hostname(host: str) -> bool:
    h = host.lower().strip(".")
    if IPV4_RE.match(h):
        return True
    if NUMERIC_HOST_RE.search(h) or PTR_HINT_RE.search(h):
        return True
    labels = h.split(".")
    if labels and HEX_LABEL_RE.match(labels[0]) and len(labels[0]) >= 16:
        return True
    if VPS_LABEL_RE.search(h) and any(
        x in h
        for x in (
            "amazonaws",
            "ovh",
            "linode",
            "digitalocean",
            "googleusercontent",
            "azure",
            "cloudapp",
        )
    ):
        return True
    return False


@lru_cache(maxsize=200_000)
def registrable(host: str | None) -> str | None:
    if not host:
        return None
    h = host.lower().strip().strip(".")
    if not h or IPV4_RE.match(h) or ":" in h:
        return None
    if is_junk_suffix(h):
        return None
    ext = _extract(h)
    if not ext.domain or not ext.suffix:
        return None
    reg = f"{ext.domain}.{ext.suffix}".lower()
    if reg in JUNK_REGISTRABLE or is_isp_domain(reg) or is_junk_suffix(reg):
        return None
    return reg


def is_reseller_org(org: str | None) -> bool:
    if not org:
        return False
    low = org.lower()
    return any(p in low for p in RESELLER_ORG_PHRASES)


def is_provider_domain(domain: str) -> bool:
    """Hosting / telco reseller registrable domains — never a cyber software ICP."""
    d = domain.lower().strip()
    if d in JUNK_REGISTRABLE or d in HOSTING_REGISTRABLE or d in TELCO_REGISTRABLE:
        return True
    if any(s in d for s in PROVIDER_DOMAIN_SUBSTRINGS):
        return True
    if d.endswith(".host") or d.endswith(".servers"):
        return True
    head = d.split(".")[0]
    if head in {"servers", "hosting", "vps", "dedi", "dedibox", "colo", "datacenter", "datacentre"}:
        return True
    if d.endswith(".cloud") and head not in {
        "azure",
        "google",
        "aws",
        "salesforce",
        "adobe",
        "oracle",
    }:
        # Most *.cloud domains in scan data are VPS brands, not buyers.
        if len(head) <= 12 and not re.search(r"[0-9]{3,}", head):
            return True
    if is_isp_domain(d):
        return True
    return False


def infer_icp_tag(domain: str, n_hosts: int) -> str:
    d = domain.lower()
    if any(
        d.endswith(s) for s in (".edu", ".ac.uk", ".ac.jp", ".ac.th", ".edu.tw", ".edu.mx", ".edu.au", ".edu.co")
    ):
        return "edu"
    if any(
        x in d
        for x in (
            ".gov",
            ".gob.",
            ".govt.",
            ".mil",
            ".go.jp",
            ".go.kr",
            "gov.br",
        )
    ):
        return "gov"
    if any(x in d for x in (".health", "hospital", "clinic", "medical", "sante")):
        return "health"
    if n_hosts >= 25:
        return "enterprise"
    return "smb"


def is_isp_domain(domain: str) -> bool:
    d = domain.lower()
    if d in JUNK_REGISTRABLE:
        return True
    head = d.split(".")[0]
    if re.match(r"^as\d+$", head):
        return True
    labels = set(d.replace("-", ".").split("."))
    if labels & set(PROVIDER_DOMAIN_TOKENS):
        return True
    if any(lbl.endswith("srv") or lbl.endswith("hosting") or lbl in {"ddns", "dyndns", "no-ip", "duckdns"} for lbl in labels):
        return True
    if d.endswith((".ne.jp", ".net.tw", ".net.au", ".co.uk")) and any(
        x in d for x in ("bt", "virgin", "sky", "plus", "talktalk", "ee.co")
    ):
        return True
    labels = d.split(".")
    if any(lbl in {"adsl", "dsl", "broadband", "dynamic", "dhcp", "dialup", "cust", "res"} for lbl in labels):
        return True
    for sfx in ISP_DOMAIN_SUFFIXES:
        if sfx.startswith(".") and d.endswith(sfx):
            return True
    return False


def pick_company_domain(hostnames: list[str], domains: list[str]) -> str | None:
    """Prefer a hostname that looks like a real business, not PTR/CDN."""
    candidates: list[tuple[int, str]] = []
    seen: set[str] = set()
    for raw in list(hostnames) + list(domains):
        if looks_like_infra_hostname(raw):
            continue
        reg = registrable(raw)
        if not reg or reg in seen or is_provider_domain(reg):
            continue
        seen.add(reg)
        score = 0
        # Prefer hostnames that include a brand-looking label (not ns1, mail, etc.)
        host = raw.lower()
        if not VPS_LABEL_RE.search(host):
            score += 2
        if host.endswith(reg) and host != reg:
            score += 1
        if len(reg) >= 8:
            score += 1
        candidates.append((score, reg))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]
