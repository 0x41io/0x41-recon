#!/usr/bin/env python3
"""
0x41 Recon - passive domain reconnaissance with AI synthesis.

Usage:
    python recon.py example.com
    python recon.py example.com --json results.json
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

from collectors import certspotter, crtsh
import history
BANNER = r"""
 ██████╗ ██╗  ██╗██╗  ██╗ ██╗
██╔═████╗╚██╗██╔╝██║  ██║███║   0x41 Recon  v0.2
██║██╔██║ ╚███╔╝ ███████║╚██║
████╔╝██║ ██╔██╗ ╚════██║ ██║   passive OSINT
╚██████╔╝██╔╝ ██╗     ██║ ██║
 ╚═════╝ ╚═╝  ╚═╝     ╚═╝ ╚═╝
"""

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def clean_domain(raw: str) -> str:
    """Accept 'https://www.Example.com/path' and turn it into 'example.com'-style input."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)  # strip scheme
    d = d.split("/")[0].split(":")[0]  # strip path and port
    if not DOMAIN_RE.match(d):
        raise ValueError(f"'{raw}' doesn't look like a valid domain")
    return d


def main() -> int:
    print(BANNER)
    parser = argparse.ArgumentParser(description="0x41 Recon - passive domain recon")
    parser.add_argument("domain", help="target domain, e.g. example.com")
    parser.add_argument("--json", metavar="FILE", help="save raw results to a JSON file")
    parser.add_argument("--ai", action="store_true", help="have Claude write a summary report (needs ANTHROPIC_API_KEY)")
    args = parser.parse_args()

    try:
        domain = clean_domain(args.domain)
    except ValueError as e:
        print(f"[x] {e}")
        return 1

    results = {"target": domain, "sources": {}, "errors": {}}
    print(f"[*] Target: {domain}")

    # Certificate Transparency: try both sources, merge whatever succeeds
    for name, module in [("crt.sh", crtsh), ("Cert Spotter", certspotter)]:
        print(f"[*] Querying certificate transparency logs ({name})...")
        try:
            r = module.collect(domain)
            results["sources"][r["source"]] = r
            print(f"[+] {name}: {r['certificates_seen']} certificates -> {r['subdomain_count']} hostnames")
        except RuntimeError as e:
            results["errors"][name] = str(e)
            print(f"[!] {name} unavailable: {e}")

    if not results["sources"]:
        print("[x] All certificate sources failed. They're free services - try again in a few minutes.")
        return 1

    all_subs = sorted({s for r in results["sources"].values() for s in r["subdomains"]})
    results["subdomains"] = all_subs
    print(f"\n[+] {len(all_subs)} unique hostnames total:\n")
    for sub in all_subs:
        print(f"    {sub}")

    # Change detection: compare with the last scan of this domain, then save this one
    previous = history.load_last(domain)
    saved_path = history.save(domain, all_subs)
    if previous is None:
        print(f"\n[*] First scan of {domain} - saved as baseline ({saved_path})")
    else:
        changes = history.compare(previous, all_subs)
        results["changes"] = changes
        print(f"\n[*] Changes since last scan ({changes['previous_scan']}):")
        if not changes["added"] and not changes["removed"]:
            print("    No changes.")
        for sub in changes["added"]:
            print(f"    [NEW]  {sub}")
        for sub in changes["removed"]:
            print(f"    [GONE] {sub}")
        if results["errors"] and changes["removed"]:
            print("    [!] A source failed this run, so GONE hosts may just be missing data.")
    if args.ai:
        print("\n[*] Asking Claude to analyze the results...")
        try:
            import analysis
            summary, model = analysis.summarize(results)
        except Exception as e:  # missing key, network, API errors
            print(f"[x] AI summary failed: {e}")
        else:
            os.makedirs("reports", exist_ok=True)
            stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
            path = os.path.join("reports", f"{domain}_{stamp}.md")
            header = (
                f"# 0x41 Recon Report: {domain}\n\n"
                f"*Generated {datetime.now():%Y-%m-%d %H:%M} · "
                f"sources: {', '.join(results['sources'])} · "
                f"{len(all_subs)} hostnames · model: {model}*\n\n"
            )
            with open(path, "w") as f:
                f.write(header + summary + "\n")
            print("\n" + summary)
            print(f"\n[+] Report saved to {path}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Saved results to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
