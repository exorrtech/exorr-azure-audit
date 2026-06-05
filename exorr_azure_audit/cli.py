#!/usr/bin/env python3
"""EXORR Azure Audit — Scan Azure/Entra ID for security misconfigurations."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .scanner import AzureScanner
from .report import AuditReportGenerator


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="exorr-azure-audit",
        description="EXORR Azure Audit — Azure/Entra ID security misconfiguration scanner",
        epilog="Walk with the void. EXORR Security",
    )
    p.add_argument("-s", "--subscription-id", required=False, help="Azure subscription ID (or set AZURE_SUBSCRIPTION_ID)")
    p.add_argument("-t", "--tenant-id", required=False, help="Azure AD tenant ID (or set AZURE_TENANT_ID)")
    p.add_argument("-c", "--checks", default=None, help="Comma-separated checks to run (default: all). Options: rbac,keyvault,nsg,entra,storage,appservice")
    p.add_argument("--severity-threshold", choices=["low", "medium", "high", "critical"], default="low", help="Min severity to report (default: low)")
    p.add_argument("-o", "--output", default=None, help="Output file path. Default: azure-audit-{timestamp}.json")
    p.add_argument("--format", choices=["json", "markdown", "html"], default="json", help="Report format (default: json)")
    p.add_argument("--offline", action="store_true", help="Run offline checks only (parse exported ARM/Entra JSON files)")
    p.add_argument("--arm-file", default=None, help="Path to exported ARM template JSON for offline analysis")
    p.add_argument("--entra-file", default=None, help="Path to exported Entra ID directory settings JSON")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    p.add_argument("--dry-run", action="store_true", help="List checks without running them")
    p.add_argument("-v", "--version", action="version", version="%(prog)s 1.0.0")
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    print(f"\n  EXORR Azure Audit v1.0.0")
    print(f"  ========================")

    scanner = AzureScanner(
        subscription_id=args.subscription_id,
        tenant_id=args.tenant_id,
        checks_filter=args.checks,
        verbose=args.verbose,
    )

    if args.dry_run:
        checks = scanner.list_checks()
        print(f"\n  Available checks ({len(checks)}):")
        for c in checks:
            print(f"    [{c['id']}] {c['name']} — {c['description']}")
        print(f"\n  Dry run — no checks executed.")
        return 0

    # Run audit
    if args.offline:
        if not args.arm_file and not args.entra_file:
            print("[!] Offline mode requires --arm-file and/or --entra-file", file=sys.stderr)
            return 1
        results = scanner.run_offline(
            arm_file=args.arm_file,
            entra_file=args.entra_file,
        )
    else:
        # Check for az CLI auth
        if not scanner.has_auth():
            print("[!] No Azure authentication found. Use 'az login' or set AZURE_SUBSCRIPTION_ID + service principal env vars.", file=sys.stderr)
            print("    Alternatively, use --offline mode with exported JSON files.", file=sys.stderr)
            return 1
        results = scanner.run_live()

    # Generate report
    reporter = AuditReportGenerator(
        results=results,
        format=args.format,
        severity_threshold=args.severity_threshold,
    )

    output_path = args.output or f"azure-audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{args.format}"
    reporter.save(output_path)

    # Summary
    findings = [r for r in results if r.get("status") == "FAIL"]
    passed = [r for r in results if r.get("status") == "PASS"]
    print(f"\n  ========================")
    print(f"  Audit complete")
    print(f"    Checks run:  {len(results)}")
    print(f"    Findings:    {len(findings)}")
    print(f"    Passed:      {len(passed)}")
    print(f"    Report:      {output_path}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
