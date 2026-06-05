"""Azure security scanner — live and offline check execution."""

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .checks.registry import CHECK_REGISTRY, OfflineCheckRegistry


class AzureScanner:
    """Scan Azure subscriptions and Entra ID tenants for misconfigurations."""

    def __init__(
        self,
        subscription_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        checks_filter: Optional[str] = None,
        verbose: bool = False,
    ):
        self.subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
        self.tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID", "")
        self.verbose = verbose
        self.checks_filter = (
            [c.strip() for c in checks_filter.split(",")] if checks_filter else None
        )

    def has_auth(self) -> bool:
        """Check if Azure CLI authentication is available."""
        try:
            result = subprocess.run(
                ["az", "account", "show", "--output", "json"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                account = json.loads(result.stdout)
                if not self.subscription_id:
                    self.subscription_id = account.get("id", "")
                if not self.tenant_id:
                    self.tenant_id = account.get("tenantId", "")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return False

    def list_checks(self) -> List[Dict[str, Any]]:
        """List all available security checks."""
        checks = []
        for check_id, check_info in CHECK_REGISTRY.items():
            if self.checks_filter and check_id not in self.checks_filter:
                continue
            checks.append({
                "id": check_id,
                "name": check_info["name"],
                "description": check_info["description"],
                "severity": check_info["severity"],
                "category": check_info["category"],
            })
        return checks

    def _az_cli(self, *args: str) -> Optional[Dict[str, Any]]:
        """Run an az CLI command and return parsed JSON output."""
        cmd = ["az"] + list(args) + ["--output", "json"]
        if self.subscription_id:
            cmd.extend(["--subscription", self.subscription_id])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return None

    def run_live(self) -> List[Dict[str, Any]]:
        """Run checks against a live Azure subscription via az CLI."""
        results = []

        for check_id, check in CHECK_REGISTRY.items():
            if self.checks_filter and check_id not in self.checks_filter:
                continue

            if self.verbose:
                print(f"  Running: {check['name']}...")

            try:
                status, detail = check["run_fn"](self)
            except Exception as e:
                status, detail = "ERROR", str(e)

            results.append({
                "check_id": check_id,
                "check_name": check["name"],
                "category": check["category"],
                "severity": check["severity"],
                "description": check["description"],
                "status": status,
                "detail": detail,
                "remediation": check.get("remediation", ""),
            })

        return results

    def run_offline(
        self,
        arm_file: Optional[str] = None,
        entra_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Run checks against exported JSON files (offline mode)."""
        results = []
        arm_data = {}
        entra_data = {}

        if arm_file:
            with open(arm_file, "r") as f:
                arm_data = json.load(f)

        if entra_file:
            with open(entra_file, "r") as f:
                entra_data = json.load(f)

        offline_registry = OfflineCheckRegistry()

        for check_id, check in offline_registry.checks.items():
            try:
                status, detail = check["run_fn"](arm_data, entra_data)
            except Exception as e:
                status, detail = "ERROR", str(e)

            results.append({
                "check_id": check_id,
                "check_name": check["name"],
                "category": check["category"],
                "severity": check["severity"],
                "description": check["description"],
                "status": status,
                "detail": detail,
                "remediation": check.get("remediation", ""),
            })

        return results
