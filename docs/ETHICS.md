# Ethics & Safety Boundaries — SentinelAI

This project follows the safety boundaries required by the CS-2106
Information Security Group Project Handbook, Section 8, and standard
industry practice for building security tooling.

## What this project does NOT do

- **It never scans, attacks, or probes a public or third-party website,
  network, or account without explicit authorization.** The
  Vulnerability Scanner module enforces this in code (`app/modules/vuln_scanner/router.py`):
  it refuses any scan target that is not `localhost`/`127.0.0.1` or a
  host an Admin has explicitly added to the `authorized_scan_targets`
  table after confirming ownership/authorization.
- **It never creates, hosts, or executes real malware.** The Malware
  Detection module is trained on a public, academic dataset of
  *static features already extracted* from malicious and benign files
  (ClaMP — Classification of Malware with PE headers). No malicious
  binary is ever downloaded, stored, or run by this project.
- **It never uses real victims' data.** All training data is public,
  synthetic, or benchmark academic datasets (NSL-KDD for network
  traffic, a public phishing-URL dataset, ClaMP for malware
  features) — never scraped from real people or organizations without
  consent.

## Why this matters beyond the course

Scanning systems without authorization is a criminal offense in most
jurisdictions (in Pakistan, under the Prevention of Electronic Crimes
Act, 2016). Treating "authorized target only" as a hard constraint in
the code — not just a README note — is standard practice for any
security tool, academic or professional.

## Recommended local test targets for the Vulnerability Scanner demo

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — run
  locally via `docker run -p 3000:3000 bkimminich/juice-shop`
- [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) — run locally via Docker
- Your own deployed instance of a site you built (e.g. this project's
  own dashboard, once deployed)

Both are deliberately vulnerable applications built for security
education and are safe, legal targets for this kind of scanning.

## Known scope limitations (by design, not oversight)

- **The alert feed and admin-only toggles (security headers, live
  monitor on/off) are global, not per-user.** Every logged-in user reads
  the same shared alert table and sees the same toggle state. This is
  intentional for a single-tenant classroom demo — the whole point of
  the "unified dashboard" is one shared view of everything happening
  across the five modules — but it is not how a multi-tenant SOC product
  would be built. A real multi-organization deployment would need
  per-user/per-org scoping on both the alert feed and these toggles.
