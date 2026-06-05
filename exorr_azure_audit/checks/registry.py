"""Security check registry — all Azure/Entra ID security checks."""

import json
from typing import Any, Dict, List, Optional, Tuple

# Type alias for check result: (status, detail)
CheckResult = Tuple[str, str]


def _check_rbac_no_owner(scanner) -> CheckResult:
    """Check for excessive Owner role assignments."""
    data = scanner._az_cli("role", "assignment", "list", "--role", "Owner")
    if data is None:
        return "SKIP", "Could not retrieve role assignments"
    owners = [a for a in data if a.get("roleDefinition", {}).get("roleName") == "Owner" or a.get("principalName")]
    if len(owners) > 5:
        return "FAIL", f"{len(owners)} principals have Owner role - exceeds recommended maximum of 5"
    return "PASS", f"{len(owners)} principals with Owner role (within limit)"


def _check_keyvault_purge(scanner) -> CheckResult:
    """Check if Key Vaults have purge protection enabled."""
    data = scanner._az_cli("keyvault", "list")
    if data is None:
        return "SKIP", "Could not list Key Vaults"
    unprotected = []
    for kv in data:
        name = kv.get("name", "")
        try:
            props = scanner._az_cli("keyvault", "show", "--name", name)
            if props and not props.get("properties", {}).get("enablePurgeProtection", False):
                unprotected.append(name)
        except Exception:
            pass
    if unprotected:
        return "FAIL", f"Key Vaults without purge protection: {', '.join(unprotected)}"
    return "PASS", "All Key Vaults have purge protection enabled"


def _check_nsg_open_ingress(scanner) -> CheckResult:
    """Check for NSGs with overly permissive inbound rules."""
    data = scanner._az_cli("network", "nsg", "list")
    if data is None:
        return "SKIP", "Could not list NSGs"
    open_nsgs = []
    for nsg in data:
        name = nsg.get("name", "")
        rg = nsg.get("resourceGroup", "")
        try:
            rules = scanner._az_cli("network", "nsg", "rule", "list", "--resource-group", rg, "--nsg-name", name)
            if rules:
                for rule in rules:
                    if (rule.get("access") == "Allow"
                        and rule.get("direction") == "Inbound"
                        and rule.get("sourceAddressPrefix") in ("*", "0.0.0.0", "0.0.0.0/0", "Internet")
                        and rule.get("destinationPortRange") in ("*", "0-65535", "22", "3389")):
                        open_nsgs.append(f"{name}/{rule.get('name', '?')}")
        except Exception:
            pass
    if open_nsgs:
        return "FAIL", f"Open inbound rules found: {', '.join(open_nsgs[:5])}"
    return "PASS", "No overly permissive inbound NSG rules detected"


def _check_entra_mfa(scanner) -> CheckResult:
    """Check if MFA is enabled for all users in Entra ID."""
    data = scanner._az_cli("ad", "user", "list", "--query", "[].{id:id,displayName:displayName}")
    if data is None:
        return "SKIP", "Could not list Entra ID users"
    total = len(data)
    if total > 0:
        return "WARN", f"{total} users found - verify MFA enforcement via conditional access policies"
    return "PASS", "No users found or MFA appears enforced"


def _check_storage_public_access(scanner) -> CheckResult:
    """Check for storage accounts with public blob access."""
    data = scanner._az_cli("storage", "account", "list")
    if data is None:
        return "SKIP", "Could not list storage accounts"
    public = []
    for sa in data:
        name = sa.get("name", "")
        try:
            props = scanner._az_cli("storage", "account", "show", "--name", name)
            if props and props.get("allowBlobPublicAccess", True):
                public.append(name)
        except Exception:
            pass
    if public:
        return "FAIL", f"Storage accounts with public blob access: {', '.join(public)}"
    return "PASS", "All storage accounts have public access disabled"


def _check_appservice_https(scanner) -> CheckResult:
    """Check App Services for HTTPS-only enforcement."""
    data = scanner._az_cli("webapp", "list")
    if data is None:
        return "SKIP", "Could not list App Services"
    no_https = []
    for app in data:
        name = app.get("name", "")
        rg = app.get("resourceGroup", "")
        try:
            config = scanner._az_cli("webapp", "show", "--name", name, "--resource-group", rg)
            if config and not config.get("httpsOnly", False):
                no_https.append(name)
        except Exception:
            pass
    if no_https:
        return "FAIL", f"App Services without HTTPS-only: {', '.join(no_https)}"
    return "PASS", "All App Services enforce HTTPS"


CHECK_REGISTRY: Dict[str, Dict[str, Any]] = {
    "rbac-owner-count": {
        "name": "Excessive Owner Role Assignments",
        "category": "rbac",
        "severity": "high",
        "description": "Too many principals with Owner role increases blast radius of compromised accounts",
        "remediation": "Use least-privilege roles (Contributor, Reader). Limit Owners to break-glass accounts.",
        "run_fn": _check_rbac_no_owner,
    },
    "keyvault-purge-protection": {
        "name": "Key Vault Purge Protection",
        "category": "keyvault",
        "severity": "critical",
        "description": "Key Vaults without purge protection can have secrets permanently deleted by attackers",
        "remediation": "Enable purge protection on all Key Vaults: az keyvault update --name <kv> --enable-purge-protection true",
        "run_fn": _check_keyvault_purge,
    },
    "nsg-open-ingress": {
        "name": "Overly Permissive NSG Rules",
        "category": "nsg",
        "severity": "high",
        "description": "NSGs allowing inbound from * on sensitive ports (SSH/RDP) expose resources to the internet",
        "remediation": "Restrict source IP ranges. Use Just-In-Time access for SSH/RDP.",
        "run_fn": _check_nsg_open_ingress,
    },
    "entra-mfa-enforcement": {
        "name": "Entra ID MFA Enforcement",
        "category": "entra",
        "severity": "critical",
        "description": "Users without MFA are vulnerable to credential stuffing and phishing attacks",
        "remediation": "Enable conditional access policies requiring MFA for all users.",
        "run_fn": _check_entra_mfa,
    },
    "storage-public-access": {
        "name": "Storage Account Public Access",
        "category": "storage",
        "severity": "high",
        "description": "Storage accounts with public blob access can leak sensitive data",
        "remediation": "Disable public access: az storage account update --name <sa> --allow-blob-public-access false",
        "run_fn": _check_storage_public_access,
    },
    "appservice-https-only": {
        "name": "App Service HTTPS Enforcement",
        "category": "appservice",
        "severity": "medium",
        "description": "App Services allowing HTTP traffic are vulnerable to MITM attacks",
        "remediation": "Enable HTTPS-only: az webapp update --name <app> --resource-group <rg> --https-only true",
        "run_fn": _check_appservice_https,
    },
}


class OfflineCheckRegistry:
    """Checks that run against exported JSON files without Azure access."""

    def __init__(self):
        self.checks: Dict[str, Dict[str, Any]] = {
            "offline-rbac-owner": {
                "name": "RBAC Owner Count (Offline)",
                "category": "rbac",
                "severity": "high",
                "description": "Check ARM template for excessive Owner role assignments",
                "remediation": "Reduce Owner assignments. Use least-privilege roles.",
                "run_fn": self._offline_rbac,
            },
            "offline-keyvault-purge": {
                "name": "Key Vault Purge Protection (Offline)",
                "category": "keyvault",
                "severity": "critical",
                "description": "Check ARM template for Key Vaults missing purge protection",
                "remediation": "Add enablePurgeProtection: true to all Key Vault resources.",
                "run_fn": self._offline_keyvault,
            },
            "offline-nsg-open": {
                "name": "Open NSG Rules (Offline)",
                "category": "nsg",
                "severity": "high",
                "description": "Check ARM template for NSGs with open inbound rules",
                "remediation": "Restrict sourceAddressPrefix and destinationPortRange in NSG rules.",
                "run_fn": self._offline_nsg,
            },
            "offline-storage-public": {
                "name": "Storage Public Access (Offline)",
                "category": "storage",
                "severity": "high",
                "description": "Check ARM template for storage accounts with public access",
                "remediation": "Set allowBlobPublicAccess: false on storage accounts.",
                "run_fn": self._offline_storage,
            },
            "offline-entra-guest": {
                "name": "Entra ID Guest Access (Offline)",
                "category": "entra",
                "severity": "medium",
                "description": "Check Entra ID export for unrestricted guest access",
                "remediation": "Restrict guest access in Entra ID directory settings.",
                "run_fn": self._offline_entra_guest,
            },
            "offline-https-only": {
                "name": "HTTPS-Only Enforcement (Offline)",
                "category": "appservice",
                "severity": "medium",
                "description": "Check ARM template for web apps missing HTTPS-only",
                "remediation": "Set httpsOnly: true on all Microsoft.Web/sites resources.",
                "run_fn": self._offline_https,
            },
        }

    def _find_resources(self, arm_data: dict, resource_type: str) -> list:
        resources = arm_data.get("resources", [])
        return [r for r in resources if r.get("type") == resource_type]

    def _offline_rbac(self, arm_data: dict, entra_data: dict) -> CheckResult:
        assignments = self._find_resources(arm_data, "Microsoft.Authorization/roleAssignments")
        owners = [a for a in assignments if "Owner" in json.dumps(a.get("properties", {}))]
        if len(owners) > 5:
            return "FAIL", f"{len(owners)} Owner role assignments found in ARM template"
        return "PASS", f"{len(owners)} Owner assignments (within limit)"

    def _offline_keyvault(self, arm_data: dict, entra_data: dict) -> CheckResult:
        kvs = self._find_resources(arm_data, "Microsoft.KeyVault/vaults")
        unprotected = []
        for kv in kvs:
            props = kv.get("properties", {})
            if not props.get("enablePurgeProtection", False):
                unprotected.append(kv.get("name", "unknown"))
        if unprotected:
            return "FAIL", f"Key Vaults without purge protection: {', '.join(unprotected)}"
        return "PASS", "All Key Vaults have purge protection"

    def _offline_nsg(self, arm_data: dict, entra_data: dict) -> CheckResult:
        nsgs = self._find_resources(arm_data, "Microsoft.Network/networkSecurityGroups")
        open_rules = []
        for nsg in nsgs:
            for rule in nsg.get("properties", {}).get("securityRules", []):
                rp = rule.get("properties", {})
                if (rp.get("access") == "Allow"
                    and rp.get("direction") == "Inbound"
                    and rp.get("sourceAddressPrefix") in ("*", "0.0.0.0", "0.0.0.0/0", "Internet")
                    and rp.get("destinationPortRange") in ("*", "0-65535", "22", "3389")):
                    open_rules.append(f"{nsg.get('name', '?')}/{rule.get('name', '?')}")
        if open_rules:
            return "FAIL", f"Open inbound rules: {', '.join(open_rules[:5])}"
        return "PASS", "No overly permissive NSG rules"

    def _offline_storage(self, arm_data: dict, entra_data: dict) -> CheckResult:
        storages = self._find_resources(arm_data, "Microsoft.Storage/storageAccounts")
        public = []
        for sa in storages:
            props = sa.get("properties", {})
            if props.get("allowBlobPublicAccess", True):
                public.append(sa.get("name", "unknown"))
        if public:
            return "FAIL", f"Storage accounts with public access: {', '.join(public)}"
        return "PASS", "All storage accounts have public access disabled"

    def _offline_entra_guest(self, arm_data: dict, entra_data: dict) -> CheckResult:
        if not entra_data:
            return "SKIP", "No Entra ID data provided"
        guest_policy = entra_data.get("guestUserRoleId", "")
        if guest_policy == "10dae51f-b6af-4082-bd4b-af8c0141bc6e":
            return "PASS", "Guest access is restricted"
        return "FAIL", f"Guest access policy may be overly permissive (roleId: {guest_policy})"

    def _offline_https(self, arm_data: dict, entra_data: dict) -> CheckResult:
        sites = self._find_resources(arm_data, "Microsoft.Web/sites")
        no_https = []
        for site in sites:
            if not site.get("properties", {}).get("httpsOnly", False):
                no_https.append(site.get("name", "unknown"))
        if no_https:
            return "FAIL", f"Web apps without HTTPS-only: {', '.join(no_https)}"
        return "PASS", "All web apps enforce HTTPS"
