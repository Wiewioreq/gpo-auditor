# GPO Auditor

**GPO Audit System Pro v3.1** – Advanced Group Policy Objects Security Auditing Tool for Active Directory.

## Features

- Security vulnerability detection (cpassword, weak settings, SMBv1, NTLMv1, RDP issues, …)
- Interactive HTML dashboard with Chart.js charts
- Excel reports with full formatting and charts
- Email / Microsoft Teams notifications
- Change tracking between scan runs
- Progress bars and coloured terminal output
- Comprehensive file logging with rotation
- Orphaned GPO detection (AD ↔ SYSVOL mismatch)
- Password from environment variable or interactive prompt

## Installation

```bash
pip install -r gpo_auditor/requirements.txt
```

## Usage

```bash
# Run as a module (recommended)
python3 -m gpo_auditor.main --config config.yaml

# Or directly
python3 gpo_auditor/main.py --config config.yaml

# Security scan only
python3 -m gpo_auditor.main --config config.yaml --security-only

# Compare two GPOs
python3 -m gpo_auditor.main --config config.yaml --compare-gpo "GPO1" "GPO2"

# Track changes since last run
python3 -m gpo_auditor.main --config config.yaml --track-changes

# Enforce LDAPS (fail if insecure)
python3 -m gpo_auditor.main --config config.yaml --require-ldaps
```

## Modular Package Structure

```
gpo_auditor/
├── __init__.py          # Public API re-exports
├── main.py              # CLI entry point (argparse + orchestration)
├── config.py            # Config loading/validation, ConfigError
├── logging_setup.py     # setup_logging(), get_logger()
├── console.py           # Colors, ProgressBar, print_banner, colored, icon, h()
├── ad.py                # ADConnection class, global flags
├── gpo.py               # GPO listing, SYSVOL analysis, OU links, WMI filters
├── parser_registry.py   # parse_registry_pol()
├── parser_gpp.py        # parse_gpp_preferences()
├── parser_scripts.py    # parse_scripts()
├── security.py          # SecurityAnalyzer class
├── reports.py           # save_json/csv/excel/html
├── change_tracking.py   # Scan caching and comparison
├── notifications.py     # Email and Teams notifications
├── dashboard.py         # Dashboard metric helpers
├── missing_modules.py   # High-level orchestration stubs
├── requirements.txt
└── README.md
```

## Configuration

Copy and edit `config.yaml`:

```yaml
ad:
  server: ldap://dc.example.com
  user: DOMAIN\audit-user
  password: PROMPT          # or ENV:MY_PASSWORD_VAR or plain text
  base_dn: CN=Policies,CN=System,DC=example,DC=com
  ldap_ou_base: DC=example,DC=com
  allow_insecure_ldap: false
  tls:
    validate: true

paths:
  sysvol: /mnt/sysvol/Policies
  output_dir: ./reports

options:
  generate_json: true
  generate_csv: true
  generate_excel: true
  generate_html: true
  parse_registry: true
  parse_gpp: true
  parse_scripts: true

notifications:
  enabled: false
  email:
    enabled: false
    smtp_server: smtp.example.com
    from: audit@example.com
    to: [security@example.com]
  teams:
    enabled: false
    webhook_url: https://outlook.office.com/webhook/...
```

## Author

Pawel – Created for UK Job Interview Portfolio.
