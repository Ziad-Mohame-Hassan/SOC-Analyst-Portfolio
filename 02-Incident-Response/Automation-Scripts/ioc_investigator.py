#!/usr/bin/env python3
"""
IOC Investigator - Automated IOC lookup tool
Author: SOC Portfolio Project
Description: Checks IPs, domains, and file hashes against threat intel sources
"""

import requests
import json
import sys
import re

# ============================================================
# CONFIG - Add your API keys here
# ============================================================
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # https://www.virustotal.com/
OTX_API_KEY = "YOUR_OTX_API_KEY"        # https://otx.alienvault.com/

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_ip(value):
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, value))

def is_hash(value):
    return len(value) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in value)

def is_domain(value):
    return "." in value and not is_ip(value)

# ============================================================
# VIRUSTOTAL CHECKS
# ============================================================

def vt_check_ip(ip):
    print(f"\n[*] Checking IP on VirusTotal: {ip}")
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print(f"    ✅ Harmless:   {stats.get('harmless', 0)}")
        print(f"    ⚠️  Suspicious: {stats.get('suspicious', 0)}")
        print(f"    ❌ Malicious:  {stats.get('malicious', 0)}")
        return stats
    else:
        print(f"    [!] Error: {r.status_code}")
        return None

def vt_check_domain(domain):
    print(f"\n[*] Checking Domain on VirusTotal: {domain}")
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print(f"    ✅ Harmless:   {stats.get('harmless', 0)}")
        print(f"    ⚠️  Suspicious: {stats.get('suspicious', 0)}")
        print(f"    ❌ Malicious:  {stats.get('malicious', 0)}")
        return stats
    else:
        print(f"    [!] Error: {r.status_code}")
        return None

def vt_check_hash(file_hash):
    print(f"\n[*] Checking Hash on VirusTotal: {file_hash}")
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        name = data["data"]["attributes"].get("meaningful_name", "Unknown")
        print(f"    File Name: {name}")
        print(f"    ✅ Harmless:   {stats.get('harmless', 0)}")
        print(f"    ⚠️  Suspicious: {stats.get('suspicious', 0)}")
        print(f"    ❌ Malicious:  {stats.get('malicious', 0)}")
        return stats
    else:
        print(f"    [!] Error: {r.status_code} - Hash not found or API issue")
        return None

# ============================================================
# OTX CHECK
# ============================================================

def otx_check(ioc, ioc_type):
    print(f"\n[*] Checking on AlienVault OTX: {ioc}")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    type_map = {"ip": "IPv4", "domain": "domain", "hash": "file"}
    otx_type = type_map.get(ioc_type, "domain")
    
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general"
    r = requests.get(url, headers=headers)
    
    if r.status_code == 200:
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        print(f"    📊 Found in {pulse_count} OTX Pulses (threat reports)")
        if pulse_count > 0:
            print(f"    ⚠️  This IOC has been reported by the community!")
        return pulse_count
    else:
        print(f"    [!] Error: {r.status_code}")
        return None

# ============================================================
# MAIN INVESTIGATOR
# ============================================================

def investigate(ioc):
    print(f"\n{'='*50}")
    print(f"🔍 INVESTIGATING: {ioc}")
    print(f"{'='*50}")
    
    if is_ip(ioc):
        ioc_type = "ip"
        print(f"[*] IOC Type: IP Address")
        vt_check_ip(ioc)
        otx_check(ioc, ioc_type)
    elif is_hash(ioc):
        ioc_type = "hash"
        print(f"[*] IOC Type: File Hash")
        vt_check_hash(ioc)
        otx_check(ioc, ioc_type)
    elif is_domain(ioc):
        ioc_type = "domain"
        print(f"[*] IOC Type: Domain")
        vt_check_domain(ioc)
        otx_check(ioc, ioc_type)
    else:
        print(f"[!] Unknown IOC type: {ioc}")

# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    print("""
    ██╗ ██████╗  ██████╗    ██╗███╗   ██╗██╗   ██╗███████╗███████╗████████╗
    ██║██╔═══██╗██╔════╝    ██║████╗  ██║██║   ██║██╔════╝██╔════╝╚══██╔══╝
    ██║██║   ██║██║         ██║██╔██╗ ██║██║   ██║█████╗  ███████╗   ██║   
    ██║██║   ██║██║         ██║██║╚██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   
    ██║╚██████╔╝╚██████╗    ██║██║ ╚████║ ╚████╔╝ ███████╗███████║   ██║   
    ╚═╝ ╚═════╝  ╚═════╝    ╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   
    IOC Investigator v1.0 - SOC Portfolio Tool
    """)
    
    if len(sys.argv) > 1:
        # Single IOC from command line
        investigate(sys.argv[1])
    else:
        # Interactive mode
        print("Enter IOCs to investigate (IP, Domain, or Hash). Type 'quit' to exit.\n")
        while True:
            ioc = input("Enter IOC: ").strip()
            if ioc.lower() == "quit":
                break
            if ioc:
                investigate(ioc)
