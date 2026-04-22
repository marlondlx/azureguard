"""
AzureGuard - Compliance Rules Engine
Evaluates Azure resources against security and governance policies.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceResult:
    rule_id: str
    rule_name: str
    resource_id: str
    resource_name: str
    resource_type: str
    passed: bool
    severity: Severity
    message: str
    remediation: str


@dataclass
class ComplianceRule:
    rule_id: str
    name: str
    description: str
    severity: Severity
    applies_to: list[str]  # resource type substrings
    check: Callable[[dict], tuple[bool, str]]
    remediation: str


# ── Rule definitions ──────────────────────────────────────────────────────────

RULES: list[ComplianceRule] = [

    # Storage Account rules
    ComplianceRule(
        rule_id="STG-001",
        name="Storage: HTTPS traffic only",
        description="Storage accounts must enforce HTTPS-only traffic.",
        severity=Severity.HIGH,
        applies_to=["microsoft.storage/storageaccounts"],
        check=lambda p: (
            p.get("https_only") is True,
            "HTTPS-only is enabled" if p.get("https_only") else "HTTPS-only is NOT enforced — HTTP traffic allowed",
        ),
        remediation="Set 'Secure transfer required' to Enabled in the Storage Account configuration.",
    ),
    ComplianceRule(
        rule_id="STG-002",
        name="Storage: Blob public access disabled",
        description="Storage accounts must not allow public blob access.",
        severity=Severity.CRITICAL,
        applies_to=["microsoft.storage/storageaccounts"],
        check=lambda p: (
            p.get("public_access") is False or p.get("blob_public_access") is False,
            "Public blob access is disabled" if (p.get("public_access") is False) else "Public blob access is ENABLED — data may be publicly exposed",
        ),
        remediation="Disable 'Allow Blob public access' on the storage account to prevent anonymous access.",
    ),
    ComplianceRule(
        rule_id="STG-003",
        name="Storage: Minimum TLS version",
        description="Storage accounts should use TLS 1.2 or higher.",
        severity=Severity.MEDIUM,
        applies_to=["microsoft.storage/storageaccounts"],
        check=lambda p: (
            p.get("minimum_tls_version") in ("TLS1_2", "TLS1_3"),
            f"TLS version is {p.get('minimum_tls_version', 'unknown')}" + ("" if p.get("minimum_tls_version") in ("TLS1_2", "TLS1_3") else " — upgrade required"),
        ),
        remediation="Set minimum TLS version to TLS 1.2 in the storage account configuration.",
    ),

    # Virtual Machine rules
    ComplianceRule(
        rule_id="VM-001",
        name="VM: Resource tagging",
        description="Virtual machines must have at minimum 'owner' and 'environment' tags.",
        severity=Severity.LOW,
        applies_to=["microsoft.compute/virtualmachines"],
        check=lambda p: (False, "Tags evaluated at resource level — see resource metadata"),
        remediation="Add 'owner' and 'environment' tags to all virtual machines for cost tracking and governance.",
    ),
    ComplianceRule(
        rule_id="VM-002",
        name="VM: OS disk size reasonable",
        description="OS disks larger than 512 GB should be reviewed for cost optimization.",
        severity=Severity.INFO,
        applies_to=["microsoft.compute/virtualmachines"],
        check=lambda p: (
            (p.get("os_disk_size_gb") or 0) <= 512,
            f"OS disk size is {p.get('os_disk_size_gb', 'unknown')} GB" + (" — review for cost" if (p.get("os_disk_size_gb") or 0) > 512 else ""),
        ),
        remediation="Review VM OS disk size and consider resizing if over-provisioned.",
    ),

    # NSG rules
    ComplianceRule(
        rule_id="NSG-001",
        name="NSG: No wildcard inbound rules",
        description="Network Security Groups must not allow inbound traffic from any source on any port.",
        severity=Severity.CRITICAL,
        applies_to=["microsoft.network/networksecuritygroups"],
        check=lambda p: (
            not p.get("has_wildcard_inbound", False),
            "No wildcard inbound rules found" if not p.get("has_wildcard_inbound") else f"WILDCARD INBOUND RULES DETECTED: {p.get('open_inbound_rules', [])}",
        ),
        remediation="Remove or restrict wildcard inbound rules. Use specific IP ranges and ports instead of '*'.",
    ),

    # General tagging
    ComplianceRule(
        rule_id="GOV-001",
        name="Governance: Resource tagging",
        description="All resources must have at minimum an 'environment' tag.",
        severity=Severity.LOW,
        applies_to=[""],  # applies to all
        check=lambda p: (False, "Tags evaluated at resource level"),
        remediation="Apply consistent tagging policy: environment, owner, cost-center, project.",
    ),
]


class ComplianceEngine:
    """Evaluates a list of resource snapshots against defined rules."""

    def evaluate(self, snapshots: list[dict]) -> list[ComplianceResult]:
        results = []
        for snap in snapshots:
            rtype = (snap.get("type") or "").lower()
            tags = snap.get("tags") or {}
            props = snap.get("properties") or {}

            for rule in RULES:
                applies = any(rt in rtype for rt in rule.applies_to) if any(rule.applies_to) else True

                # Special handling for tag-based rules
                if rule.rule_id == "GOV-001":
                    passed = "environment" in tags
                    message = "Has 'environment' tag" if passed else "Missing 'environment' tag"
                elif rule.rule_id == "VM-001":
                    passed = "owner" in tags and "environment" in tags
                    message = "Has required tags" if passed else f"Missing tags: {[t for t in ['owner','environment'] if t not in tags]}"
                elif applies:
                    passed, message = rule.check(props)
                else:
                    continue

                results.append(ComplianceResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    resource_id=snap.get("resource_id", ""),
                    resource_name=snap.get("name", ""),
                    resource_type=snap.get("type", ""),
                    passed=passed,
                    severity=rule.severity,
                    message=message,
                    remediation=rule.remediation if not passed else "",
                ))

        return results

    def compute_score(self, results: list[ComplianceResult]) -> dict:
        """Compute an overall compliance score (0-100)."""
        if not results:
            return {"score": 100, "total": 0, "passed": 0, "failed": 0, "by_severity": {}}

        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }

        total_weight = sum(weights[r.severity] for r in results)
        passed_weight = sum(weights[r.severity] for r in results if r.passed)
        score = round((passed_weight / total_weight) * 100) if total_weight > 0 else 100

        by_severity = {}
        for sev in Severity:
            relevant = [r for r in results if r.severity == sev]
            by_severity[sev.value] = {
                "total": len(relevant),
                "passed": sum(1 for r in relevant if r.passed),
                "failed": sum(1 for r in relevant if not r.passed),
            }

        return {
            "score": score,
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
            "by_severity": by_severity,
        }
