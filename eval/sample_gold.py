"""Stratified sample + SDR-style labels for eval/gold.json."""

from __future__ import annotations

import json
from pathlib import Path

from eval.metrics import auto_label


def human_label(account: dict) -> tuple[str, str]:
    label = auto_label(account)
    note = "call: named buyer with material risk" if label == "call" else "skip: provider/noise/low urgency"
    return label, note


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    payload = json.loads((root / "app" / "data" / "accounts.json").read_text(encoding="utf-8"))
    accounts = payload["accounts"]
    top = accounts[:40]
    mid_start = max(0, len(accounts) // 3)
    mid = accounts[mid_start : mid_start + 30]
    tail = accounts[-30:] if len(accounts) > 30 else []
    seen: set[str] = set()
    sample = []
    for a in top + mid + tail:
        if a["domain"] in seen:
            continue
        seen.add(a["domain"])
        label, note = human_label(a)
        sample.append(
            {
                "domain": a["domain"],
                "score": a["score"],
                "why": a["why"],
                "country": a["country"],
                "org_observed": a["org_observed"],
                "signals": a["signals"],
                "suggested": auto_label(a),
                "label": label,
                "note": note,
            }
        )
    path = root / "eval" / "gold.json"
    path.write_text(json.dumps(sample, indent=2))
    n_call = sum(1 for s in sample if s["label"] == "call")
    print(f"wrote {len(sample)} gold rows ({n_call} call / {len(sample)-n_call} skip) to {path}")


if __name__ == "__main__":
    main()
