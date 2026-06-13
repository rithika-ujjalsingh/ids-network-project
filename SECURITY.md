# Security Policy

## Project Scope

This repository contains an **Intrusion Detection System (IDS)** built for
educational and authorized security-research purposes. It captures and
analyzes network traffic on the host it runs on.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | ✅ Actively maintained |
| < 1.0   | ❌ Not maintained     |

## Reporting a Vulnerability

If you discover a security vulnerability in this project (e.g. a flaw in
the detection logic, an injection point in the Flask API, dependency
vulnerabilities, etc.), please report it responsibly:

1. **Do not** open a public GitHub issue describing the vulnerability.
2. Email the maintainer directly at **rithisingh2020@gmail.com** with:
   - A clear description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. You can expect an initial response within **5 business days**.
4. Once confirmed, a fix will be prioritized and a security advisory /
   patch release will follow. Credit will be given to the reporter
   (unless anonymity is requested).

## Responsible Use & Legal Notice

This tool performs **live packet capture** and traffic analysis. It is
intended strictly for:

- Personal lab / home network monitoring
- Educational use (e.g. learning IDS concepts, Scapy, Flask)
- Authorized penetration testing / blue-team exercises with **explicit
  written permission** from the network owner

> ⚠️ Running this tool against networks or systems you do not own or do
> not have explicit authorization to monitor may violate the **Information
> Technology Act, 2000 (India)**, the **Computer Fraud and Abuse Act
> (US)**, or equivalent laws in your jurisdiction. The author and
> contributors assume no liability for misuse of this software.

## Known Security Considerations

- **Raw socket / packet capture access** requires elevated (root/admin)
  privileges — only run this on trusted hosts.
- The Flask development server (`app.run()`) is **not production-hardened**.
  Do not expose it directly to the internet; place it behind a reverse
  proxy / VPN, or use a production WSGI server (e.g. Gunicorn) with proper
  authentication if remote access is required.
- The SQLite alert database (`alerts.db`) may contain sensitive network
  metadata (IP addresses, traffic patterns). It is excluded from version
  control via `.gitignore` — do not commit it.
- No authentication is currently implemented on the dashboard/API. If
  deploying beyond `localhost`, add an authentication layer before
  exposing `/api/*` routes.

## Dependency Security

This project depends on `Flask` and `Scapy`. Keep dependencies up to date:

```bash
pip list --outdated
pip install -U -r requirements.txt
```

Consider enabling GitHub's **Dependabot alerts** on this repository for
automated dependency vulnerability notifications.
