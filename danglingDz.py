#!/bin/python3
#
# Author: Shivaditya Singh Tomar (@0xtomar)
# GitHub: https://github.com/0xtomar/DanglingDz
#
# Description:
# - Enumerates subdomains via crt.sh OR accepts a subdomain list directly
# - Checks CNAME records for dangling DNS
# - Supports real-time dangling DNS output
# - Saves results to CSV
#

import requests
import json
import argparse
import validators
import dns.resolver
import dns.exception
import sys
import csv
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------- ARGUMENTS --------------------

parser = argparse.ArgumentParser()
parser.add_argument(
    "-l", "--list",
    help="File containing root domains (one per line) to enumerate via crt.sh"
)
parser.add_argument(
    "-s", "--subdomains",
    help="File containing subdomains (one per line). Skips crt.sh enumeration"
)
parser.add_argument(
    "-v", "--verbose",
    action="store_true",
    help="Verbose output"
)
parser.add_argument(
    "--realtime",
    action="store_true",
    help="Print dangling CNAMEs immediately when found"
)

args = parser.parse_args()

if not args.list and not args.subdomains:
    print("Specify either -l <domains_file> or -s <subdomains_file>")
    sys.exit(1)

# -------------------- LOAD INPUT --------------------

all_subdomains = set()
subdomain_file = "subdomains.txt"

# Case 1: Subdomains provided directly
if args.subdomains:
    try:
        with open(args.subdomains, "r") as f:
            for line in f:
                sub = line.strip()
                if sub and validators.domain(sub):
                    all_subdomains.add(sub)

        print(f"\033[93m[ + ]\033[0m Loaded {len(all_subdomains)} subdomains from {args.subdomains}")

    except Exception as e:
        print(f"\033[91m[ - ]\033[0m Failed to read subdomains file: {e}")
        sys.exit(1)

# Case 2: Enumerate via crt.sh
elif args.list:
    try:
        with open(args.list, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"\033[91m[ - ]\033[0m Failed to read domain list: {e}")
        sys.exit(1)

    for domain in tqdm(domains, desc="Querying crt.sh", unit="domain"):
        crt_url = f"https://crt.sh/?Identity={domain}&output=json"

        if args.verbose:
            print(f"\033[93m[ + ]\033[0m Querying crt.sh for {domain}")

        try:
            response = requests.get(crt_url, timeout=15)

            if response.status_code == 200 and response.text:
                json_response = json.loads(response.text)

                for result in json_response:
                    subdomain = result.get("common_name", "")
                    if validators.domain(subdomain):
                        all_subdomains.add(subdomain)

                if args.verbose:
                    print(f"\033[92m[ ✔ ]\033[0m Retrieved subdomains for {domain}")

        except Exception as e:
            print(f"\033[91m[ - ]\033[0m Error querying {domain}: {e}")

    with open(subdomain_file, "w") as f:
        for sub in sorted(all_subdomains):
            f.write(sub + "\n")

    print(f"\033[93m[ + ]\033[0m {len(all_subdomains)} unique subdomains saved to {subdomain_file}")

# -------------------- DNS CHECKING --------------------

found_cnames = []
dangling_domains = []

def cname_lookup(sub):
    if args.verbose:
        print(f"\033[93m[ + ]\033[0m Checking CNAME for {sub}")

    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(sub, "CNAME")

        for rdata in answer:
            cname = str(rdata.target)

            try:
                resolver.resolve(cname, "A")
                found_cnames.append((sub, cname, "Resolves"))

                if args.verbose:
                    print(f"\033[92m[ ✔ ]\033[0m {sub} -> {cname} (Resolves)")

            except dns.exception.DNSException:
                dangling_domains.append((sub, cname, "Dangling"))

                if args.realtime:
                    print(f"\033[91m[ ! ] Dangling NOW:\033[0m {sub} -> {cname}")

                if args.verbose:
                    print(f"\033[91m[ ! ]\033[0m {sub} -> {cname} (Dangling)")

    except dns.exception.DNSException:
        pass

# -------------------- EXECUTION --------------------

if all_subdomains:
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(cname_lookup, sub) for sub in all_subdomains]
        for _ in tqdm(as_completed(futures), total=len(futures), desc="Checking CNAMEs", unit="subdomain"):
            pass

# -------------------- OUTPUT --------------------

csv_file = "cnames_report.csv"
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Subdomain", "CNAME", "Status"])
    writer.writerows(found_cnames + dangling_domains)

print(f"\n\033[93m[ + ]\033[0m CSV report saved to {csv_file}")

print("\n\033[93m[ + ] Found CNAMEs:\033[0m")
for entry in found_cnames:
    print(entry)

print("\n\033[91m[ ! ] Dangling Domains:\033[0m")
for entry in dangling_domains:
    print(entry)
