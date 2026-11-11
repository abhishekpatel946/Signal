"""Proxy evaluation for the scored account queue (no conversion labels)."""

from __future__ import annotations

import json
import random
from pathlib import Path

from ingest.resolve import is_isp_domain, is_isp_org, is_junk_suffix

# High-confidence noise: these should not appear in a sales queue.
NOISE_SUBSTRINGS = (
    "amazonaws",
    "cloudflare",
    "akamai",
    "googleusercontent",
    "1e100",
    "ovh.net",
    "herokuapp",
    "vercel.app",
    "ngrok",
    "cloudfront",
)

# High-confidence "SDR would call" if risk is present.
CALL_HINTS = (
    "eol",
    "redis",
    "smb",
    "kubernetes",
    "vnc",
    "telnet",
    "hikvision",
    "dahua",
    "self-signed",
    "self_signed",
    "CVE-",
)


def is_noise_domain(domain: str) -> bool:
    d = domain.lower()
    if is_junk_suffix(d) or is_isp_domain(d):
        return True
    return any(s in d for s in NOISE_SUBSTRINGS)


BUYER_SUFFIXES = (
    ".edu",
    ".gov",
    ".gob.",
    ".govt.",
    ".ac.uk",
    ".ac.jp",
    ".mil",
)

PROVIDER_BRANDS = (
    "telecom",
    "cableonda",
    "brasiltelecom",
    "highspeedlink",
    "ukservers",
    "tilaa",
    "viviotech",
    "kylos",
    "hersheytel",
    "provalue",
    "evopc",
    "bnet.at",
)


def auto_label(account: dict) -> str:
    """SDR question: would I call this named company this week?"""
    domain = account["domain"]
    if is_noise_domain(domain) or is_isp_domain(domain):
        return "skip"
    if any(x in domain for x in PROVIDER_BRANDS):
        return "skip"
    if account.get("fit") in {
        "honeypot",
        "cdn_only",
        "hyperscaler",
        "isp_domain",
        "ptr_umbrella",
        "provider_aggregate",
    }:
        return "skip"
    risk = (
        account["signals"]["cve"]
        or account["signals"]["exposure"]
        or account["signals"]["eol"]
        or account["signals"]["iot"]
    )
    if any(domain.endswith(sfx) or sfx in domain for sfx in BUYER_SUFFIXES) and risk:
        return "call"
    if risk and account["score"] >= 40 and account.get("n_hosts", 99) <= 12 and not is_isp_org(account.get("org_observed")):
        return "call"
    if risk and account["score"] >= 50:
        return "call"
    return "skip"


def precision_at_k(accounts: list[dict], k: int) -> float:
    top = accounts[:k]
    if not top:
        return 0.0
    return sum(1 for a in top if auto_label(a) == "call") / len(top)


def noise_leak_rate(accounts: list[dict], k: int = 100) -> float:
    top = accounts[:k]
    if not top:
        return 0.0
    return sum(1 for a in top if is_noise_domain(a["domain"])) / len(top)


def high_sev_rate(accounts: list[dict], k: int) -> float:
    top = accounts[:k]
    if not top:
        return 0.0
    return sum(
        1
        for a in top
        if a["signals"]["cve"] or a["signals"]["exposure"] or a["signals"]["eol"]
    ) / len(top)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    payload = json.loads((root / "app" / "data" / "accounts.json").read_text())
    accounts = payload["accounts"]
    rng = random.Random(7)
    random_sample = [accounts[i] for i in rng.sample(range(len(accounts)), min(100, len(accounts)))]

    gold_path = root / "eval" / "gold.json"
    gold = []
    if gold_path.exists():
        gold = json.loads(gold_path.read_text())

    metrics = {
        "n_accounts": len(accounts),
        "precision_at_50": round(precision_at_k(accounts, 50), 3),
        "precision_at_100": round(precision_at_k(accounts, 100), 3),
        "noise_leak_top100": round(noise_leak_rate(accounts, 100), 3),
        "high_sev_top100": round(high_sev_rate(accounts, 100), 3),
        "high_sev_random100": round(high_sev_rate(random_sample, 100), 3),
        "call_rate_top50": round(precision_at_k(accounts, 50), 3),
        "call_rate_all_exported": round(sum(1 for a in accounts if auto_label(a) == "call") / max(1, len(accounts)), 3),
        "gold_n": len(gold),
    }
    if gold:
        by_domain = {a["domain"]: a for a in accounts}
        labeled = [g for g in gold if g["domain"] in by_domain]
        if labeled:
            agree = sum(
                1
                for g in labeled
                if (auto_label(by_domain[g["domain"]]) == "call") == (g["label"] == "call")
            )
            metrics["gold_auto_agreement"] = round(agree / len(labeled), 3)
            top_domains = {a["domain"] for a in accounts[:100]}
            gold_call_in_top = sum(1 for g in labeled if g["label"] == "call" and g["domain"] in top_domains)
            metrics["gold_call_in_top100"] = gold_call_in_top

    out = root / "eval" / "metrics.json"
    out.write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
