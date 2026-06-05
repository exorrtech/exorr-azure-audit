"""Tests for offline Azure audit scanning."""
import json
from pathlib import Path

from exorr_azure_audit.scanner import AzureScanner
from exorr_azure_audit.checks.registry import OfflineCheckRegistry, CHECK_REGISTRY


SAMPLE_DIR = Path(__file__).parent


def test_offline_keyvault_finds_vulnerable():
    """Offline scan should find Key Vault without purge protection."""
    scanner = AzureScanner()
    arm_data = json.loads((SAMPLE_DIR / "sample_arm.json").read_text())
    entra_data = json.loads((SAMPLE_DIR / "sample_entra.json").read_text())
    results = scanner.run_offline(arm_file=str(SAMPLE_DIR / "sample_arm.json"), entra_file=str(SAMPLE_DIR / "sample_entra.json"))
    kv_check = [r for r in results if r["check_id"] == "offline-keyvault-purge"]
    assert len(kv_check) == 1
    assert kv_check[0]["status"] == "FAIL"
    assert "kv-vulnerable" in kv_check[0]["detail"]


def test_offline_nsg_finds_open_rules():
    """Offline scan should find open NSG rules."""
    scanner = AzureScanner()
    results = scanner.run_offline(arm_file=str(SAMPLE_DIR / "sample_arm.json"), entra_file=str(SAMPLE_DIR / "sample_entra.json"))
    nsg_check = [r for r in results if r["check_id"] == "offline-nsg-open"]
    assert len(nsg_check) == 1
    assert nsg_check[0]["status"] == "FAIL"


def test_offline_storage_finds_public():
    """Offline scan should find storage accounts with public access."""
    scanner = AzureScanner()
    results = scanner.run_offline(arm_file=str(SAMPLE_DIR / "sample_arm.json"), entra_file=str(SAMPLE_DIR / "sample_entra.json"))
    stg_check = [r for r in results if r["check_id"] == "offline-storage-public"]
    assert len(stg_check) == 1
    assert stg_check[0]["status"] == "FAIL"
    assert "stgpublic" in stg_check[0]["detail"]


def test_offline_https_finds_violation():
    """Offline scan should find web apps without HTTPS-only."""
    scanner = AzureScanner()
    results = scanner.run_offline(arm_file=str(SAMPLE_DIR / "sample_arm.json"), entra_file=str(SAMPLE_DIR / "sample_entra.json"))
    https_check = [r for r in results if r["check_id"] == "offline-https-only"]
    assert len(https_check) == 1
    assert https_check[0]["status"] == "FAIL"
    assert "webapp-no-https" in https_check[0]["detail"]


def test_offline_entra_guest_check():
    """Offline scan should flag permissive guest access."""
    scanner = AzureScanner()
    results = scanner.run_offline(arm_file=str(SAMPLE_DIR / "sample_arm.json"), entra_file=str(SAMPLE_DIR / "sample_entra.json"))
    guest_check = [r for r in results if r["check_id"] == "offline-entra-guest"]
    assert len(guest_check) == 1
    assert guest_check[0]["status"] == "FAIL"


def test_list_checks():
    """Scanner should list all registered checks."""
    scanner = AzureScanner()
    checks = scanner.list_checks()
    assert len(checks) == len(CHECK_REGISTRY)
    ids = {c["id"] for c in checks}
    assert "rbac-owner-count" in ids
    assert "keyvault-purge-protection" in ids
