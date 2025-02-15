# DanglingDz 🕵️‍♂️

## Overview
DanglingDz is a Python tool that automates subdomain enumeration and **dangling CNAME** detection. It queries `crt.sh` for subdomains and checks if their CNAME records point to unregistered cloud services, potentially leading to **subdomain takeover**.

## Features
✅ Fetch subdomains from `crt.sh`  
✅ Multi-threaded CNAME resolution  
✅ Detects **dangling CNAMEs**  
✅ Progress bar for better tracking  
✅ Verbose mode (`-v`) for detailed output  

## Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/0xtomar/DanglingDz.git
cd DanglingDz
pip install -r requirements.txt
