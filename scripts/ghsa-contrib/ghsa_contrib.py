#!/usr/bin/env python3
"""Draft GitHub Advisory Database contributions from a CVE record.

Many CVEs reach GHSA as `type: unreviewed` with an EMPTY `vulnerabilities`
array: no ecosystem, no package name, no version range. Nothing purl-based can
match them — not Dependabot, not Trivy, not Snyk, not hibou. Meanwhile the CNA's
own record at cveawg.mitre.org already carries exact, structured, semver ranges.

This converts the second into the first.

    ./ghsa_contrib.py CVE-2026-59084 [CVE-...] [--out drafts/]

For each CVE it writes a patched OSV advisory ready to copy into a fork of
github/advisory-database, plus a PR body. It NEVER opens a PR and never edits
anything in place: review every draft before submitting.

Division of labour, which is the whole reason this is automatable:

  * version ranges   -- mechanical. CNA `versions[]` -> OSV range events, 1:1.
  * package coords   -- judgement, but PER PRODUCT, not per CVE. Curated once in
                        product-packages.json; every later CVE for that product
                        converts for free.

Deliberately conservative, because a wrong range here becomes a false positive
for every downstream consumer:

  * `lessThanOrEqual` maps to OSV `last_affected`, never to a guessed `fixed`.
    The CNA states the last affected version; naming the fix version would mean
    inventing a release number we have not verified exists.
  * refuses to touch an advisory that already carries package data, or one that
    is already github-reviewed.
  * emits the CNA record URL as the PR's public reference — contributions are
    rejected without one.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

CVE_API = "https://cveawg.mitre.org/api/cve/{cve}"
GH_ADVISORY_API = "https://api.github.com/advisories?cve_id={cve}"
RAW = ("https://raw.githubusercontent.com/github/advisory-database/main/"
       "advisories/{tier}/{year}/{month}/{ghsa}/{ghsa}.json")
HERE = pathlib.Path(__file__).resolve().parent


class Skip(Exception):
    """A CVE this tool should not touch, with the reason why."""


def get_json(url: str) -> object:
    request = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "hibou-ghsa-contrib",
    })
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def cna_ranges(cve_record: dict) -> list[dict]:
    """CNA affected[] -> [{vendor, product, ranges: [{introduced, last_affected|fixed}]}].

    Only `status: affected` versions are carried over. A version entry with
    neither an upper bound nor a bound we understand is dropped rather than
    guessed at — silence beats a fabricated range.
    """
    out = []
    for entry in cve_record["containers"]["cna"].get("affected", []):
        ranges = []
        for version in entry.get("versions", []):
            if version.get("status") != "affected":
                continue
            introduced = str(version.get("version", "")).strip()
            if not introduced:
                continue
            event = {"introduced": introduced}
            if version.get("lessThanOrEqual"):
                # Inclusive upper bound: OSV expresses this as last_affected.
                event["last_affected"] = str(version["lessThanOrEqual"]).strip()
            elif version.get("lessThan"):
                # Exclusive upper bound is exactly OSV's `fixed`.
                event["fixed"] = str(version["lessThan"]).strip()
            else:
                continue
            ranges.append(event)
        if ranges:
            out.append({
                "vendor": (entry.get("vendor") or "").strip(),
                "product": (entry.get("product") or "").strip(),
                "ranges": ranges,
            })
    return out


def osv_affected(packages: list[dict], ranges: list[dict]) -> list[dict]:
    """One OSV affected[] entry per (package x release branch)."""
    entries = []
    for package in packages:
        for event in ranges:
            events = [{"introduced": event["introduced"]}]
            if "last_affected" in event:
                events.append({"last_affected": event["last_affected"]})
            else:
                events.append({"fixed": event["fixed"]})
            entries.append({
                "package": {
                    "ecosystem": package["ecosystem"],
                    "name": package["name"],
                },
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            })
    return entries


def locate(cve: str) -> tuple[str, str, str, str]:
    """-> (ghsa_id, tier, year, month). Raises Skip when it must not be touched."""
    advisories = get_json(GH_ADVISORY_API.format(cve=cve))
    if not isinstance(advisories, list) or not advisories:
        raise Skip("no GHSA entry exists for this CVE yet")
    advisory = advisories[0]
    ghsa = advisory["ghsa_id"]
    if advisory.get("type") != "unreviewed":
        raise Skip(f"already {advisory.get('type')} — curators own it, do not patch")
    if advisory.get("vulnerabilities"):
        raise Skip("already carries package data — nothing to contribute")
    published = str(advisory.get("published_at") or "")
    if len(published) < 7:
        raise Skip("advisory has no usable published date, cannot derive its path")
    return ghsa, "unreviewed", published[:4], published[5:7]


def draft(cve: str, mapping: dict, out_dir: pathlib.Path) -> str:
    ghsa, tier, year, month = locate(cve)
    record = get_json(CVE_API.format(cve=cve))
    products = cna_ranges(record)
    if not products:
        raise Skip("CNA record carries no usable affected version ranges")

    affected: list[dict] = []
    unmapped: list[str] = []
    for product in products:
        key = f"{product['vendor']}::{product['product']}"
        entry = mapping.get(key)
        if not entry:
            unmapped.append(key)
            continue
        affected.extend(osv_affected(entry["packages"], product["ranges"]))
    if unmapped:
        raise Skip("no package mapping for " + "; ".join(unmapped)
                   + " — add it to product-packages.json first")

    path = f"advisories/{tier}/{year}/{month}/{ghsa}/{ghsa}.json"
    advisory = get_json(RAW.format(tier=tier, year=year, month=month, ghsa=ghsa))
    if advisory.get("affected"):
        # Belt and braces: the API said empty, the file disagrees. Trust the file.
        raise Skip("advisory file already has affected[] — refusing to overwrite")
    advisory["affected"] = affected

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{ghsa}.json").write_text(
        json.dumps(advisory, indent=2, ensure_ascii=False) + "\n")
    (out_dir / f"{ghsa}.pr.md").write_text(pr_body(cve, ghsa, path, products, affected))
    return (f"{cve} -> {ghsa}  {len(affected)} affected entries "
            f"({len(products)} product(s))\n    file: {path}")


def pr_body(cve, ghsa, path, products, affected) -> str:
    branches = "\n".join(
        f"| `{event['introduced']}` | "
        f"`{event.get('last_affected') or event.get('fixed')}` | "
        f"{'last affected (inclusive)' if 'last_affected' in event else 'fixed (exclusive)'} |"
        for product in products for event in product["ranges"])
    names = sorted({entry["package"]["name"] for entry in affected})
    return f"""Add affected package ranges to {ghsa} ({cve})

`{path}`

{ghsa} is `unreviewed` with an empty affected list, so no purl-based scanner —
Dependabot, Trivy, Snyk, OSV consumers — can match it. The CNA record already
publishes exact, structured ranges; this transcribes them.

**Source (public reference):** <{CVE_API.format(cve=cve)}>

Ranges, taken verbatim from `containers.cna.affected[].versions[]`:

| introduced | upper bound | bound type |
|---|---|---|
{branches}

Upper bounds are recorded as OSV `last_affected` wherever the CNA used
`lessThanOrEqual`, so no fix version is inferred.

**Packages** ({len(affected)} entries across {len(names)} artifacts):

{chr(10).join('- `' + name + '`' for name in names)}

**Question for reviewers:** the CNA identifies only the product, not the
artifact, so this mirrors the package set used by existing github-reviewed
advisories for it. That may be broader than the flaw — please narrow it if the
affected code ships in fewer artifacts.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("cves", nargs="+", metavar="CVE-ID")
    parser.add_argument("--out", type=pathlib.Path, default=HERE / "drafts")
    parser.add_argument("--mapping", type=pathlib.Path,
                        default=HERE / "product-packages.json")
    args = parser.parse_args()

    mapping = {key: value for key, value
               in json.loads(args.mapping.read_text()).items()
               if not key.startswith("_")}

    failures = 0
    for cve in args.cves:
        try:
            print("OK   " + draft(cve, mapping, args.out))
        except Skip as reason:
            print(f"SKIP {cve}: {reason}")
        except (urllib.error.URLError, KeyError, ValueError) as error:
            print(f"FAIL {cve}: {type(error).__name__}: {error}", file=sys.stderr)
            failures += 1
    if failures:
        return 1
    print(f"\nDrafts in {args.out} — review each, then one PR per advisory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
