#!/bin/python3
#
# Author: Shivaditya Singh Tomar (@0xtomar)
# GitHub: https://github.com/0xtomar/DanglingDz
#
# Description:
# This script queries crt.sh for subdomains of a provided list of domains
# and checks for CNAME records for those subdomains. If a CNAME is found,
# it checks if it resolves to an IP address or is dangling (unresolved).
# The results are saved in a CSV report and displayed in verbose mode if enabled.
#
# Dependencies:
# - requests
# - json
# - argparse
# - validators
# - dns.resolver
# - tqdm
# - concurrent.futures
#
# Usage:
# python3 script.py -l <file_with_domains.txt> -v (for verbose output)
#

import requests
import json
import argparse
import validators
import dns.resolver, dns.exception
import sys
import csv
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--list", action="store", help="(rel) path to file containing list with domains separated by newlines")
parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output")
args = parser.parse_args()

if not args.list:
    print("Specify a file with domains using -l")
    sys.exit()

# Read input domains
with open(args.list, 'r') as f:
    domains = [line.strip() for line in f.readlines() if line.strip()]

all_subdomains = set()
subdomain_file = "subdomains.txt"

# Query crt.sh for subdomains
for domain in tqdm(domains, desc="Querying crt.sh", unit="domain"):
    crt_url = f"https://crt.sh/?Identity={domain}&output=json"
    if args.verbose:
        print(f"\033[93m[ + ]\033[0m Querying crt.sh for {domain}")
    try:
        response = requests.get(crt_url)
        if response.status_code == 200 and response.text:
            json_response = json.loads(response.text)
            for result in json_response:
                subdomain = result.get("common_name", "")
                if validators.domain(subdomain):
                    all_subdomains.add(subdomain)
        if args.verbose:
            print(f"\033[92m[ ✔ ]\033[0m Successfully retrieved subdomains for {domain}")
    except Exception as e:
        print(f"\033[91m[ - ]\033[0m Error querying {domain}: {e}")

# Save unique subdomains to file
with open(subdomain_file, "w") as f:
    for sub in sorted(all_subdomains):
        f.write(sub + "\n")

print(f"\033[93m[ + ]\033[0m {len(all_subdomains)} unique subdomains saved to {subdomain_file}\n")

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
                resolver.resolve(cname, "A")  # If resolves, it's not dangling
                found_cnames.append((sub, cname, "Resolves"))
                if args.verbose:
                    print(f"\033[92m[ ✔ ]\033[0m {sub} -> {cname} (Resolves)")
            except dns.exception.DNSException:
                dangling_domains.append((sub, cname, "Dangling"))
                if args.verbose:
                    print(f"\033[91m[ ! ]\033[0m {sub} -> {cname} (Dangling)")
    except dns.exception.DNSException:
        pass

if all_subdomains:
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(cname_lookup, sub): sub for sub in all_subdomains}
        for _ in tqdm(as_completed(futures), total=len(all_subdomains), desc="Checking CNAMEs", unit="subdomain"):
            pass

# Save results in CSV format
csv_file = "cnames_report.csv"
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Subdomain", "CNAME", "Status"])
    writer.writerows(found_cnames + dangling_domains)

print(f"\033[93m[ + ]\033[0m CSV report saved to {csv_file}")

print("\n\033[93m[ + ] Found CNAMEs:\033[0m")
for entry in found_cnames:
    print(entry)
print("\n\033[91m[ ! ] Dangling Domains:\033[0m")
for entry in dangling_domains:
    print(entry)
