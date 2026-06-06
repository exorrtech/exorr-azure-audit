# EXORR Azure Audit

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![MIT License](https://img.shields.io/badge/license-MIT-green.svg)
![Version 1.0.0](https://img.shields.io/badge/version-1.0.0-orange.svg)
[![CI](https://github.com/exorrtech/exorr-azure-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/exorrtech/exorr-azure-audit/actions/workflows/ci.yml)

**Azure & Entra ID security misconfiguration scanner** — detect dangerous defaults before attackers do.

EXORR Azure Audit scans your Azure subscriptions and Entra ID tenants for common security misconfigurations. It supports **live scanning** via the Azure CLI (`az`) and **offline analysis** of exported ARM templates and Entra ID directory settings — no cloud access required.

---

## Features

- **Live scanning** — runs checks against a live Azure subscription via `az CLI`
- **Offline ARM template analysis** — audit exported ARM templates and Entra ID JSON without cloud connectivity
- **6 security checks** covering RBAC, Key Vault, NSG, Entra ID, Storage, and App Service
- **Multiple output formats** — JSON, Markdown, and HTML reports
- **Severity filtering** — filter findings by severity threshold
- **Dry-run mode** — list available checks without executing them
- **Zero runtime dependencies** — pure Python, only `az CLI` for live scans

---

## Tech Stack

`Python 3.9+` `CLI` `JSON/Markdown/HTML Reporting`

---

## Installation

```bash
pip install exorr-azure-audit
```

Or install from source:

```bash
git clone https://github.com/exorrtech/exorr-azure-audit.git
cd exorr-azure-audit
pip install .
```

For development:

```bash
pip install ".[dev]"
pytest
```

---

## Usage

### Dry-run (list checks without running)

```bash
exorr-azure-audit --dry-run
```

### Offline scan (ARM template + Entra ID export)

```bash
exorr-azure-audit --offline --arm-file template.json --entra-file entra.json --format markdown
```

### Live scan (requires `az login`)

```bash
exorr-azure-audit --subscription-id <SUB_ID> --format html -o report.html
```

### Filter by specific checks

```bash
exorr-azure-audit --checks rbac,keyvault,storage --severity-threshold high
```

---

## Security Checks

**Check ID** — **Name** — **Category** — **Severity** — **Description**

- `rbac-owner-count` — Excessive Owner Role Assignments — **RBAC** — 🔴 High — Too many Owner principals increase blast radius
- `keyvault-purge-protection` — Key Vault Purge Protection — **KeyVault** — 🔴 Critical — Vaults without purge protection can have secrets permanently deleted
- `nsg-open-ingress` — Overly Permissive NSG Rules — **NSG** — 🔴 High — NSGs allowing inbound from `*` on SSH/RDP ports
- `entra-mfa-enforcement` — Entra ID MFA Enforcement — **Entra** — 🔴 Critical — Users without MFA are vulnerable to credential attacks
- `storage-public-access` — Storage Account Public Access — **Storage** — 🔴 High — Storage accounts with public blob access can leak data
- `appservice-https-only` — App Service HTTPS Enforcement — **AppService** — 🟡 Medium — App Services allowing HTTP are vulnerable to MITM

---

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| JSON | `--format json` | Structured machine-readable report with full check metadata |
| Markdown | `--format markdown` | Human-readable report with findings summary and remediation |
| HTML | `--format html` | Styled standalone HTML report with severity color-coding |

---

## Project Structure

```
exorr-azure-audit/
├── exorr_azure_audit/
│   ├── __init__.py          # Package version & metadata
│   ├── __main__.py          # python -m entry point
│   ├── cli.py               # CLI argument parsing & main loop
│   ├── scanner.py           # AzureScanner — live & offline execution
│   ├── report.py            # AuditReportGenerator — JSON/MD/HTML output
│   └── checks/
│       ├── __init__.py
│       └── registry.py      # All check definitions (live + offline)
├── tests/
│   ├── __init__.py
│   ├── test_offline_scanner.py  # 6 passing tests
│   ├── sample_arm.json          # Sample ARM template for offline tests
│   └── sample_entra.json        # Sample Entra ID export for offline tests
├── pyproject.toml
├── LICENSE
├── README.md
└── .gitignore
```

---

## Requirements

- **Python 3.9+**
- **Azure CLI** (`az`) — required for live scanning only; not needed for offline mode

Set `AZURE_SUBSCRIPTION_ID` or pass `--subscription-id` for live scans. Authenticate with `az login` before running live checks.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

*Walk with the void. **∅ EXORR***
