"""Audit report generator for Azure security findings."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class AuditReportGenerator:
    """Generate security audit reports."""

    def __init__(self, results: List[Dict[str, Any]], format: str = "json", severity_threshold: str = "low"):
        self.results = results
        self.format = format
        self.threshold = SEVERITY_ORDER.get(severity_threshold, 4)

    def _summary(self) -> Dict[str, Any]:
        findings = [r for r in self.results if r.get("status") == "FAIL"]
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = f.get("category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_checks": len(self.results),
            "findings": len(findings),
            "passed": len([r for r in self.results if r.get("status") == "PASS"]),
            "skipped": len([r for r in self.results if r.get("status") == "SKIP"]),
            "by_severity": by_severity,
            "by_category": by_category,
        }

    def _to_json(self) -> str:
        return json.dumps({
            "scanner": "exorr-azure-audit",
            "version": "1.0.0",
            "summary": self._summary(),
            "results": self.results,
        }, indent=2, default=str)

    def _to_markdown(self) -> str:
        s = self._summary()
        lines = [
            "# EXORR Azure Audit Report",
            "",
            f"**Date:** {s['timestamp']}",
            "",
            "## Summary",
            "",
            f"- **Total Checks:** {s['total_checks']}",
            f"- **Findings:** {s['findings']}",
            f"- **Passed:** {s['passed']}",
            f"- **Skipped:** {s['skipped']}",
            "",
        ]
        findings = [r for r in self.results if r.get("status") == "FAIL"]
        if findings:
            lines.append("## Findings")
            lines.append("")
            for f in findings:
                lines.append(f"### [{f.get('severity', '?').upper()}] {f.get('check_name', 'Unknown')}")
                lines.append(f"- **Category:** {f.get('category')}")
                lines.append(f"- **Detail:** {f.get('detail')}")
                lines.append(f"- **Remediation:** {f.get('remediation')}")
                lines.append("")
        lines.append("---")
        lines.append("*Walk with the void. EXORR Security*")
        return "\n".join(lines)

    def _to_html(self) -> str:
        s = self._summary()
        sev_colors = {"critical": "#ff0040", "high": "#ff4444", "medium": "#ffaa00", "low": "#44aaff"}
        findings = [r for r in self.results if r.get("status") == "FAIL"]
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>EXORR Azure Audit</title>
<style>
:root{{--g:#00ff41;--bg:#0a0a0a;--tx:#c0c0c0}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:monospace;background:var(--bg);color:var(--tx);padding:2rem}}
h1{{color:var(--g);font-size:1.5rem;margin-bottom:1rem}}
.finding{{background:#111;border-left:3px solid #888;padding:1rem;margin:0.5rem 0;border-radius:0 8px 8px 0}}
</style></head><body>
<h1>EXORR Azure Audit Report</h1>
<p>{s['timestamp']}</p>
<p>Checks: {s['total_checks']} | Findings: {s['findings']} | Passed: {s['passed']}</p>
"""
        for f in findings:
            c = sev_colors.get(f.get("severity", ""), "#888")
            html += f"""<div class="finding" style="border-left-color:{c}">
<strong>[{f.get('severity','?').upper()}]</strong> {f.get('check_name')} — {f.get('detail')}<br>
<small>Remediation: {f.get('remediation')}</small>
</div>\n"""
        html += '<div style="margin-top:2rem;color:#333">Walk with the void. EXORR Security</div></body></html>'
        return html

    def save(self, path: str) -> None:
        content = {"json": self._to_json, "markdown": self._to_markdown, "html": self._to_html}.get(self.format, self._to_json)()
        Path(path).write_text(content, encoding="utf-8")
