# DOMINUS
### Domain Intelligence & Risk Scoring — OSINT Reconnaissance Toolkit

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey?style=flat-square)
![OSINT](https://img.shields.io/badge/Type-OSINT-blueviolet?style=flat-square)

> 🛡️ Part of the **DOMINI Suite** — a two-tool passive OSINT framework.  
> DOMINUS analyzes domains. [SENTINEL](https://github.com/KristinaSabitova/sentinel) analyzes IPs.  
> Together they map the full attack surface of any target.

---

## What is DOMINUS?

DOMINUS is a passive OSINT reconnaissance tool focused on **domains and companies**. Given a domain name, it aggregates publicly available information across six analysis phases, calculates a transparent **Risk Score from 0 to 100**, and generates a fully standalone HTML report you can open in any browser, send by email, or publish anywhere.

It was built as a direct alternative to person-focused OSINT tools like Sherlock, Holehe, or Maigret. Instead of profiling individuals, **DOMINUS profiles infrastructure** — the domain, its configuration, its exposure, and its attack surface.

---

## What does it find?

| Phase | Data collected |
|-------|---------------|
| **WHOIS** | Registrar, registrant organization, creation and expiration dates, name servers, privacy protection status |
| **DNS** | A/AAAA/MX/NS/TXT records, SPF policy and strictness, DMARC configuration and enforcement level, DKIM selector detection |
| **Subdomains** | Passive enumeration via Certificate Transparency logs (crt.sh) — no brute force, no noise |
| **Ports** | Open TCP services, version banners, and service fingerprints via nmap |
| **Headers** | Full HTTP security headers audit: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, server banner exposure |
| **LeakRadar** | Public credential leak detection via Google Dorks on Pastebin — surfaces exposed emails, password dumps, and sensitive data pastes indexed publicly |

---

## What does the Risk Score mean?

Every finding contributes weighted points to a **Risk Score from 0 to 100**:

| Score | Level | What it means |
|-------|-------|---------------|
| 0–25 | 🟢 Low | Clean configuration, minimal exposure |
| 26–50 | 🟡 Medium | Misconfigured email authentication, missing security headers |
| 51–75 | 🔴 High | DMARC not enforced, sensitive ports open, server banner exposed |
| 76–100 | 🔥 Critical | RDP/VNC/database ports exposed, credentials found in Pastebin dumps |

**The score is fully transparent.** Every point is explained in the report with the exact finding that triggered it. No black boxes.

---

## What is it useful for?

**Security analysts** use it to assess the external attack surface of a target before an engagement — what an attacker would see from the outside.

**Developers and sysadmins** use it to audit their own infrastructure — catch misconfigured DNS, missing security headers, or accidentally exposed services before someone else does.

**Red teamers** use it in the reconnaissance phase to map the target's domain infrastructure, identify subdomains, and detect email spoofing opportunities (missing DMARC).

**Students and researchers** use it to understand what public information is available about any organization, and what that information reveals about their security posture.

**Real-world scenarios where DOMINUS adds value:**

- You want to know if a company's email domain can be spoofed (DMARC/SPF audit)
- You're doing a pentest and need to map the target's subdomains passively
- You want to check if credentials from your organization have appeared in public pastes
- You're evaluating a vendor's security posture before a partnership
- You're preparing a security awareness report for a client

---

## DOMINUS + SENTINEL: the full picture

DOMINUS and SENTINEL are designed to work together. The natural workflow is:

```
1. Run DOMINUS on a domain → extracts IP addresses from DNS records
2. Take those IPs → run SENTINEL on each one
3. Cross-reference findings → complete threat picture
```

**Example with <domain>:**

```bash
# Step 1: DOMINUS extracts IPs from DNS
python dominus.py ****.es --only dns
# → Found: XX.XXX.XXX.XXX and XX.XX.XXX.XXX

# Step 2: SENTINEL analyzes each IP
python sentinel.py XX.XXX.XXX.XXX
python sentinel.py XX.XX.XXX.XXX
# → Both hosted on OVH/Wetopi, Threat Score 2/100, clean
```

**Result:** The domain has email authentication issues (DMARC p=none, SPF soft-fail), but the underlying infrastructure is clean, hosted in Europe, with no abuse history. This is the kind of nuanced conclusion a professional analyst would reach — DOMINUS and SENTINEL together make it possible in seconds.

> 🔗 See [SENTINEL](https://github.com/KristinaSabitova/sentinel) for IP-level threat intelligence.

---

## LeakRadar — Credential Leak Detection

The `leakradar` phase operates in two modes:

### Mode A — LeakRadar API *(requires `LEAKRADAR_KEY` in `.env`)*
Queries the [LeakRadar](https://leakradar.io) threat intelligence platform (5B+ credentials indexed). Returns total leaks found, breakdown by employees/clients/third-party, and sample emails. Passwords are never exposed without a paid unlock.

### Mode B — Pastebin Google Dorks *(free, no key required)*
When no API key is present, the module automatically falls back to **Google Dorking on Pastebin** — the same technique real attackers use in reconnaissance. Runs four targeted searches:

```
site:pastebin.com "target.com"
site:pastebin.com "target.com" password
site:pastebin.com "target.com" email
site:pastebin.com "target.com" credential
```

**Switching from Mode B to Mode A requires zero code changes** — just add the key to `.env`.

---

## The report

A single `.html` file. Open it in any browser. Send it to a client. No server needed.

- Animated SVG risk score ring
- Per-phase breakdown with weighted scores and progress bars
- Findings table with color-coded severity badges (Low / Medium / High / Critical)
- Numbered actionable recommendations with priority levels
- Collapsible raw data sections per phase
- **Language switcher: 🇪🇸 Spanish / 🇷🇺 Russian** — instant, no page reload
- Fully standalone — all CSS and JS inline

---

## Installation

```bash
git clone https://github.com/KristinaSabitova/dominus.git
cd dominus
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
brew install nmap        # macOS
sudo apt install nmap    # Linux
```

---

## Usage

```bash
# Full scan
.venv/bin/python dominus.py example.com

# Skip port scan (faster)
.venv/bin/python dominus.py example.com --skip ports

# DNS and headers only
.venv/bin/python dominus.py example.com --only dns headers

# Full scan + JSON export
.venv/bin/python dominus.py example.com --json
```

---

## Tech stack

| Library | Purpose |
|---------|---------|
| `python-whois` | WHOIS lookups |
| `dnspython` | DNS resolution and record parsing |
| `python-nmap` | Port scanning via nmap |
| `requests` | HTTP headers, crt.sh API, Pastebin dorks |
| `jinja2` | HTML report templating |
| `rich` | Terminal output formatting |

---

## Project structure

```
dominus/
├── dominus.py
├── requirements.txt
├── .env.example
├── dominus/
│   ├── core/
│   │   ├── engine.py        # Orchestrates phases, handles errors per phase
│   │   └── scoring.py       # Risk Score logic with weighted contributions
│   ├── modules/
│   │   ├── whois_module.py
│   │   ├── dns_module.py
│   │   ├── subdomains_module.py
│   │   ├── ports_module.py
│   │   ├── headers_module.py
│   │   └── leakradar_module.py
│   ├── report/
│   │   ├── generator.py
│   │   └── templates/report.html
│   └── utils/logger.py
└── output/
```

---

## Legal notice

DOMINUS performs **passive reconnaissance only**. It queries publicly available information — WHOIS records, DNS data, Certificate Transparency logs, public HTTP headers, and indexed Pastebin content. It does not exploit vulnerabilities, access restricted systems, or modify any data.

Always obtain proper authorization before scanning infrastructure you do not own.

---

## Author

Built for an academic cybersecurity practice at **Evolve Academy**.
Designed to demonstrate domain-level OSINT as a professional alternative to identity-focused tools.

Part of the **DOMINI Suite** alongside [SENTINEL](https://github.com/KristinaSabitova/sentinel).

---

*DOMINUS — know your target's surface before anyone else does.*
