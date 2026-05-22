#!/usr/bin/env python3
"""
GeoIP Enrichment Script — Project 3 Honeypot
Enriches Cowrie JSON logs with country, city, and ASN data
Follows same code patterns as Project 2 (argparse, [+] progress, config style)
"""

import json
import argparse
import sys
from pathlib import Path

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    print("[-] geoip2 not installed. Run: pip3 install geoip2 --break-system-packages")
    sys.exit(1)

CITY_DB = "/opt/geoip/GeoLite2-City.mmdb"
ASN_DB  = "/opt/geoip/GeoLite2-ASN.mmdb"

def lookup_ip(ip, city_reader, asn_reader):
    result = {"src_country": "Unknown", "src_country_code": "XX",
              "src_city": "Unknown", "src_asn": "Unknown", "src_org": "Unknown"}
    try:
        city = city_reader.city(ip)
        result["src_country"]      = city.country.name or "Unknown"
        result["src_country_code"] = city.country.iso_code or "XX"
        result["src_city"]         = city.city.name or "Unknown"
    except Exception:
        pass
    try:
        asn = asn_reader.asn(ip)
        result["src_asn"] = f"AS{asn.autonomous_system_number}"
        result["src_org"] = asn.autonomous_system_organization or "Unknown"
    except Exception:
        pass
    return result

def enrich(input_path, output_path):
    print(f"[+] Loading GeoIP databases...")
    city_reader = geoip2.database.Reader(CITY_DB)
    asn_reader  = geoip2.database.Reader(ASN_DB)

    print(f"[+] Reading {input_path}")
    enriched = []
    skipped  = 0
    total    = 0

    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                event = json.loads(line)
                src_ip = event.get("src_ip")
                if src_ip:
                    geo = lookup_ip(src_ip, city_reader, asn_reader)
                    event.update(geo)
                enriched.append(event)
            except json.JSONDecodeError:
                skipped += 1

    city_reader.close()
    asn_reader.close()

    print(f"[+] Enriched {len(enriched)} events ({skipped} skipped)")

    with open(output_path, "w") as f:
        for event in enriched:
            f.write(json.dumps(event) + "\n")

    print(f"[+] Output written to {output_path}")

    # Print country summary
    from collections import Counter
    countries = Counter(e.get("src_country", "Unknown")
                       for e in enriched if e.get("src_ip"))
    print(f"\n[+] Top 10 attacker countries:")
    for country, count in countries.most_common(10):
        print(f"    {count:>6} events  {country}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enrich Cowrie logs with GeoIP data")
    parser.add_argument("--input",  default="/opt/cowrie-logs/cowrie.json",
                        help="Input Cowrie JSON log")
    parser.add_argument("--output", default="/opt/cowrie-logs/cowrie_enriched.json",
                        help="Output enriched JSON log")
    args = parser.parse_args()
    enrich(args.input, args.output)
