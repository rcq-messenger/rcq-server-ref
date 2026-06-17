#!/usr/bin/env python3
"""Build the compact IP->country table the broker uses for region-scoped relay
liveness (region quorum in app/services/geoip.py).

Source: the five RIR "delegated-extended" statistics files (public, no account,
no license) — the same authoritative allocation data MaxMind/db-ip derive from.
We compile them into ONE sorted, gzipped CSV of `start_int,end_int,CC` (IPv4
only) that the server bisects at startup. Reproducible: re-run to refresh.

  python3 tools/build_geoip.py            # fetch + build -> app/data/geoip_cc.csv.gz
  python3 tools/build_geoip.py --local    # build from already-downloaded /tmp files

This is "no infra": the output is a static ~MB data file vendored in the repo,
not a runtime service or a licensed DB that needs periodic auto-updates.
"""
import gzip
import ipaddress
import os
import sys
import urllib.request

RIRS = {
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "apnic": "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
}

OUT = os.path.join(os.path.dirname(__file__), "..", "app", "data", "geoip_cc.csv.gz")


def fetch(name: str, url: str, local: bool) -> str:
    path = f"/tmp/rir_{name}.txt"
    if local and os.path.exists(path):
        return open(path, encoding="utf-8", errors="replace").read()
    print(f"  fetching {name} …", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "rcq-geoip-builder"})
    data = urllib.request.urlopen(req, timeout=120).read().decode("utf-8", "replace")
    open(path, "w", encoding="utf-8").write(data)
    return data


def parse(text: str) -> list[tuple[int, int, str]]:
    rows = []
    for line in text.splitlines():
        # registry|cc|type|start|value|date|status[|...]
        f = line.split("|")
        if len(f) < 7 or f[2] != "ipv4":
            continue
        cc, start, value, status = f[1], f[3], f[4], f[6]
        if len(cc) != 2 or not cc.isalpha():
            continue
        if status not in ("allocated", "assigned"):
            continue
        try:
            s = int(ipaddress.IPv4Address(start))
            n = int(value)
        except (ValueError, ipaddress.AddressValueError):
            continue
        if n <= 0:
            continue
        rows.append((s, s + n - 1, cc.upper()))
    return rows


def main() -> None:
    local = "--local" in sys.argv
    all_rows: list[tuple[int, int, str]] = []
    for name, url in RIRS.items():
        all_rows += parse(fetch(name, url, local))
    all_rows.sort(key=lambda r: r[0])
    # Merge adjacent same-country ranges to shrink the table.
    merged: list[list] = []
    for s, e, cc in all_rows:
        if merged and merged[-1][2] == cc and s == merged[-1][1] + 1:
            merged[-1][1] = e
        else:
            merged.append([s, e, cc])
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with gzip.open(OUT, "wt", encoding="ascii") as fh:
        for s, e, cc in merged:
            fh.write(f"{s},{e},{cc}\n")
    print(f"wrote {len(merged)} ranges -> {os.path.relpath(OUT)} "
          f"({os.path.getsize(OUT)//1024} KB)", file=sys.stderr)


if __name__ == "__main__":
    main()
