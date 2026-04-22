"""
AzureGuard - Azure Resource Collector
Connects to Azure via Service Principal and collects resource data.
"""

import os
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class ResourceSnapshot:
    resource_id: str
    name: str
    type: str
    resource_group: str
    location: str
    tags: dict
    properties: dict
    collected_at: str


class AzureCollector:
    """Collects resource metadata from Azure subscriptions."""

    def __init__(self):
        self.subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
        self.credential = ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )
        self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
        self.storage_client = StorageManagementClient(self.credential, self.subscription_id)
        self.network_client = NetworkManagementClient(self.credential, self.subscription_id)

    def collect_all_resources(self) -> list[ResourceSnapshot]:
        """Collect all resources across the subscription."""
        logger.info("Starting full resource collection...")
        snapshots = []
        now = datetime.now(timezone.utc).isoformat()

        for resource in self.resource_client.resources.list():
            snap = ResourceSnapshot(
                resource_id=resource.id,
                name=resource.name,
                type=resource.type,
                resource_group=resource.id.split("/")[4] if resource.id else "unknown",
                location=resource.location or "global",
                tags=resource.tags or {},
                properties=self._enrich_properties(resource),
                collected_at=now,
            )
            snapshots.append(snap)

        logger.info(f"Collected {len(snapshots)} resources.")
        return snapshots

    def _enrich_properties(self, resource) -> dict:
        """Fetch extended properties for known resource types."""
        rtype = (resource.type or "").lower()
        rg = resource.id.split("/")[4] if resource.id else None

        try:
            if "microsoft.compute/virtualmachines" in rtype and rg:
                vm = self.compute_client.virtual_machines.get(rg, resource.name, expand="instanceView")
                statuses = vm.instance_view.statuses if vm.instance_view else []
                power_state = next(
                    (s.display_status for s in statuses if s.code and s.code.startswith("PowerState")),
                    "unknown",
                )
                return {
                    "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                    "os_type": vm.storage_profile.os_disk.os_type.value if vm.storage_profile and vm.storage_profile.os_disk else None,
                    "power_state": power_state,
                    "os_disk_size_gb": vm.storage_profile.os_disk.disk_size_gb if vm.storage_profile and vm.storage_profile.os_disk else None,
                }

            if "microsoft.storage/storageaccounts" in rtype and rg:
                account = self.storage_client.storage_accounts.get_properties(rg, resource.name)
                return {
                    "sku": account.sku.name if account.sku else None,
                    "kind": account.kind,
                    "https_only": account.enable_https_traffic_only,
                    "public_access": account.allow_blob_public_access,
                    "minimum_tls_version": account.minimum_tls_version,
                    "blob_public_access": account.allow_blob_public_access,
                }

            if "microsoft.network/networksecuritygroups" in rtype and rg:
                nsg = self.network_client.network_security_groups.get(rg, resource.name)
                rules = nsg.security_rules or []
                open_rules = [
                    r.name for r in rules
                    if r.direction == "Inbound"
                    and r.access == "Allow"
                    and r.destination_port_range in ("*", "0-65535")
                    and r.source_address_prefix in ("*", "Internet", "0.0.0.0/0")
                ]
                return {
                    "rules_count": len(rules),
                    "open_inbound_rules": open_rules,
                    "has_wildcard_inbound": len(open_rules) > 0,
                }

        except Exception as e:
            logger.warning(f"Could not enrich {resource.name}: {e}")

        return {}

    def save_snapshot(self, snapshots: list[ResourceSnapshot], output_dir: str = "data") -> str:
        """Save collected snapshots to a JSON file."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"snapshot_{timestamp}.json")

        data = [asdict(s) for s in snapshots]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Snapshot saved to {filepath}")
        return filepath


if __name__ == "__main__":
    collector = AzureCollector()
    snapshots = collector.collect_all_resources()
    collector.save_snapshot(snapshots)
