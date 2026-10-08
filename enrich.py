"""
Host enrichment: resolve hostnames to IPs, then look up who hosts each IP.

- DNS: uses your normal system resolver (a standard DNS lookup, the same
  thing a browser does). This asks DNS servers, not the target's web
  servers, but it is less passive than reading CT logs, so it's opt-in
  via --enrich.
- ASN / provider: Team Cymru's free IP-to-ASN whois service (bulk mode,
  no API key). Tells you the network owner (e.g. AMAZON-02, CLOUDFLARENET)
  and country for each IP.
"""

import ipaddress
import socket
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

CYMRU_HOST = ("whois.cymru.com", 43)


def _resolve_one(host: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return sorted(set(ips))
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return []


def resolve(hosts: list[str], workers: int = 32) -> dict[str, list[str]]:
    """Resolve many hostnames in parallel. Unresolvable hosts map to []."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(hosts, pool.map(_resolve_one, hosts)))


def asn_lookup(ips: list[str], timeout: int = 20) -> dict[str, dict]:
    """Bulk IP -> ASN lookup via Team Cymru whois. Returns {ip: info}."""
    if not ips:
        return {}
    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    try:
        with socket.create_connection(CYMRU_HOST, timeout=timeout) as s:
            s.sendall(query.encode())
            chunks = []
            while chunk := s.recv(65536):
                chunks.append(chunk)
    except OSError as e:
        raise RuntimeError(f"Team Cymru ASN lookup failed: {e}")
    return parse_cymru("".join(c.decode(errors="replace") for c in chunks))


def parse_cymru(text: str) -> dict[str, dict]:
    """Parse lines like:
    15169   | 8.8.8.8 | 8.8.8.0/24 | US | arin | 2023-12-28 | GOOGLE, US
    """
    out = {}
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7 or parts[0] in ("AS", "") or line.startswith("Bulk mode"):
            continue
        asn, ip, prefix, cc, registry, _, as_name = parts[:7]
        if asn == "NA":
            continue
        # "AMAZON-02, US" -> "AMAZON-02"
        name = as_name.rsplit(",", 1)[0].strip() if "," in as_name else as_name
        out[ip] = {"asn": f"AS{asn}", "as_name": name, "prefix": prefix, "country": cc}
    return out


def enrich(hosts: list[str]) -> dict:
    """Resolve + ASN-enrich hosts. Returns per-host data and a provider summary."""
    resolved = resolve(hosts)

    public_ips = sorted({
        ip for ips in resolved.values() for ip in ips
        if ipaddress.ip_address(ip).is_global
    })
    asn_error = None
    try:
        asn = asn_lookup(public_ips)
    except RuntimeError as e:
        asn, asn_error = {}, str(e)

    per_host = {}
    for host in hosts:
        ips = resolved.get(host, [])
        entry = {"ips": ips}
        if not ips:
            entry["provider"] = None  # in CT logs but no DNS record now
        elif not ipaddress.ip_address(ips[0]).is_global:
            entry["provider"] = "PRIVATE IP"  # internal address in public DNS
        else:
            info = asn.get(ips[0], {})
            entry.update(info)
            entry["provider"] = info.get("as_name", "unknown")
        per_host[host] = entry

    providers = Counter(e["provider"] or "no DNS record" for e in per_host.values())
    return {
        "hosts": per_host,
        "providers": dict(providers.most_common()),
        "resolved": sum(1 for e in per_host.values() if e["ips"]),
        "unique_ips": len({ip for e in per_host.values() for ip in e["ips"]}),
        "private_ip_hosts": [h for h, e in per_host.items() if e["provider"] == "PRIVATE IP"],
        "asn_error": asn_error,
    }
