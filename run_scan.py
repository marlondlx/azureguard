"""
AzureGuard - Standalone scan runner.
Used by GitHub Actions and local CLI.
"""

import sys
import json
from collector.azure_collector import AzureCollector
from alerts.compliance_engine import ComplianceEngine
from alerts.alert_manager import AlertManager


def main():
    print("=" * 50)
    print("  AzureGuard — Compliance Scan")
    print("=" * 50)

    print("\n[1/3] Collecting Azure resources...")
    collector = AzureCollector()
    snapshots = collector.collect_all_resources()
    filepath = collector.save_snapshot(snapshots)
    print(f"      {len(snapshots)} resources collected → {filepath}")

    print("\n[2/3] Evaluating compliance rules...")
    engine = ComplianceEngine()
    snap_dicts = [s.__dict__ for s in snapshots]
    results = engine.evaluate(snap_dicts)
    score = engine.compute_score(results)

    print(f"\n{'─'*50}")
    print(f"  COMPLIANCE SCORE: {score['score']}/100")
    print(f"  Passed : {score['passed']}")
    print(f"  Failed : {score['failed']}")
    print(f"{'─'*50}")

    for sev, data in score["by_severity"].items():
        if data["total"] > 0:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")
            print(f"  {emoji} {sev.upper():10} {data['failed']:3} failed / {data['total']:3} total")

    print("\n[3/3] Sending alert notifications...")
    AlertManager().send_alert_digest(results, score)

    print("\n✓ Scan complete.\n")

    # Exit with non-zero if critical failures exist
    critical_failures = score["by_severity"].get("critical", {}).get("failed", 0)
    sys.exit(1 if critical_failures > 0 else 0)


if __name__ == "__main__":
    main()
