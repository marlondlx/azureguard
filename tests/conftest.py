import pytest
from datetime import datetime, timezone

@pytest.fixture
def storage_account_secure():
    return {"resource_id": "/sub/rg/Microsoft.Storage/storageAccounts/safe","name": "safestorage","type": "Microsoft.Storage/storageAccounts","resource_group": "rg-prod","location": "brazilsouth","tags": {"environment": "production", "owner": "devops"},"properties": {"https_only": True,"public_access": False,"blob_public_access": False,"minimum_tls_version": "TLS1_2"},"collected_at": datetime.now(timezone.utc).isoformat()}

@pytest.fixture
def storage_account_insecure():
    return {"resource_id": "/sub/rg/Microsoft.Storage/storageAccounts/bad","name": "badstorage","type": "Microsoft.Storage/storageAccounts","resource_group": "rg-dev","location": "brazilsouth","tags": {},"properties": {"https_only": False,"public_access": True,"blob_public_access": True,"minimum_tls_version": "TLS1_0"},"collected_at": datetime.now(timezone.utc).isoformat()}

@pytest.fixture
def nsg_safe():
    return {"resource_id": "/sub/rg/Microsoft.Network/networkSecurityGroups/nsg-prod","name": "nsg-prod","type": "Microsoft.Network/networkSecurityGroups","resource_group": "rg-prod","location": "brazilsouth","tags": {"environment": "production"},"properties": {"rules_count": 3,"open_inbound_rules": [],"has_wildcard_inbound": False},"collected_at": datetime.now(timezone.utc).isoformat()}

@pytest.fixture
def nsg_open():
    return {"resource_id": "/sub/rg/Microsoft.Network/networkSecurityGroups/nsg-open","name": "nsg-open","type": "Microsoft.Network/networkSecurityGroups","resource_group": "rg-dev","location": "brazilsouth","tags": {},"properties": {"rules_count": 5,"open_inbound_rules": ["allow-all-inbound"],"has_wildcard_inbound": True},"collected_at": datetime.now(timezone.utc).isoformat()}

@pytest.fixture
def virtual_machine_tagged():
    return {"resource_id": "/sub/rg/Microsoft.Compute/virtualMachines/vm-01","name": "vm-web-01","type": "Microsoft.Compute/virtualMachines","resource_group": "rg-prod","location": "brazilsouth","tags": {"environment": "production", "owner": "web-team"},"properties": {"vm_size": "Standard_B2s","os_disk_size_gb": 128},"collected_at": datetime.now(timezone.utc).isoformat()}

@pytest.fixture
def virtual_machine_untagged():
    return {"resource_id": "/sub/rg/Microsoft.Compute/virtualMachines/vm-dev","name": "vm-dev-01","type": "Microsoft.Compute/virtualMachines","resource_group": "rg-dev","location": "brazilsouth","tags": {},"properties": {"vm_size": "Standard_B4ms","os_disk_size_gb": 1024},"collected_at": datetime.now(timezone.utc).isoformat()}