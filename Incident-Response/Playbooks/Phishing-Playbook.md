# 📧 Incident Response Playbook: Phishing Attack

**Version:** 1.0  
**Last Updated:** 2025  
**Severity:** High  

---

## 1. Detection & Triage

### Indicators to Look For
- Suspicious sender domain (lookalike domains)
- Mismatched Reply-To address
- Urgency language in subject
- Suspicious attachments (.exe, .js, .doc with macros)
- Suspicious links (shortened URLs, non-standard domains)

### Initial Questions
- [ ] How many users received the email?
- [ ] Did any user click the link or open the attachment?
- [ ] Is the link still active?
- [ ] Was any credential entered?

---

## 2. Containment

```bash
# Block sender domain in email gateway
# Example: Exchange PowerShell
Set-TransportRule -Name "Block Phishing Domain" -SenderDomainIs "malicious-domain.com" -DeleteMessage $true

# Block malicious URL at proxy/firewall
# Add to blocklist: http://malicious-url.com
```

- [ ] Quarantine the phishing email from all mailboxes
- [ ] Block malicious URL at web proxy
- [ ] Block sender domain in email gateway
- [ ] Isolate affected machines (if user clicked)

---

## 3. Investigation

### Email Header Analysis
```
Key headers to check:
- Received: (trace email path)
- X-Originating-IP: (original sender IP)
- Authentication-Results: (SPF, DKIM, DMARC results)
- Return-Path: (actual reply destination)
```

### IOC Extraction
- [ ] Extract URLs from email body
- [ ] Extract attachments and hash them (MD5, SHA256)
- [ ] Check IPs and domains on VirusTotal
- [ ] Check file hashes on VirusTotal / MalwareBazaar

### VirusTotal Check (Python)
```python
import requests

VT_API_KEY = "your_api_key"

def check_url(url):
    headers = {"x-apikey": VT_API_KEY}
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
    return response.json()

# Usage
result = check_url("http://suspicious-url.com")
print(result)
```

---

## 4. Eradication

- [ ] Delete phishing email from all affected mailboxes
- [ ] Remove any downloaded malicious files
- [ ] Revoke compromised credentials
- [ ] Force password reset for affected users

---

## 5. Recovery

- [ ] Re-enable isolated systems after clean scan
- [ ] Monitor affected accounts for 72 hours
- [ ] Verify no persistence mechanisms remain

---

## 6. Lessons Learned

- [ ] Document timeline of events
- [ ] Identify detection gaps
- [ ] Update email filtering rules
- [ ] Conduct user awareness training

---

## Useful Resources
- [PhishTool](https://www.phishtool.com/) - Email analysis
- [MXToolbox](https://mxtoolbox.com/EmailHeaders.aspx) - Header analysis
- [VirusTotal](https://www.virustotal.com/) - IOC lookup
