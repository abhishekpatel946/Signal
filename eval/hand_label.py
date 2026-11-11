"""Apply reviewed SDR labels on the stratified gold sample."""

from __future__ import annotations

import json
from pathlib import Path

# Independent of auto_label: would an ASM/vuln-mgmt SDR dial this week?
FORCE_SKIP = {
    "digicom-al.net",
    "ikexpress.com",
    "tilaa.cloud",
    "ukservers.com",
    "bnet.at",
    "evopc.pl",
    "hersheytel.net",
    "highspeedlink.net",
    "provalue.net",
    "cableonda.net",
    "brasiltelecom.net.br",
    "viviotech.net",
    "kylos.pl",
    "t-online.hu",
    "tpnet.pl",
    "hostmonster.com",
    "cloud-ips.com",
    "rcn.com",
    "forpsi.net",
    "zap.cloud",
    "free.fr",
    "uvtnet.cz",
    "advance.com.ar",
    "yrless.net.nz",
    "cin.net",
    "ltl.icu",
}

FORCE_CALL = {
    "ipn.mx",
    "scu.edu.tw",
    "alfenas.mg.gov.br",
    "yili.com",
    "de-novo.biz",
    "brouzdal.cz",
    "bihar.gov.in",
    "uniandes.edu.co",
    "unina.it",
    "nccu.edu.tw",
    "kfa-juelich.de",
    "plottechnologygroup.com",
    "asklawyers.com",
    "pge.rj.gov.br",
    "timeshipping.com.cn",
    "siag.it",
    "imprensaoficial.com.br",
    "stmarys.nsw.edu.au",
    "ashghal.gov.qa",
    "keyubu.com",
}


def main() -> None:
    path = Path("eval/gold.json")
    rows = json.loads(path.read_text(encoding="utf-8"))
    for row in rows:
        d = row["domain"]
        if d in FORCE_SKIP:
            row["label"] = "skip"
            row["note"] = "hand: provider / telco / hoster — not this ICP"
        elif d in FORCE_CALL:
            row["label"] = "call"
            row["note"] = "hand: named institution or business with a real footprint"
        # else keep suggested/auto
    path.write_text(json.dumps(rows, indent=2))
    n_call = sum(1 for r in rows if r["label"] == "call")
    print(f"gold {len(rows)} rows, {n_call} call")


if __name__ == "__main__":
    main()
