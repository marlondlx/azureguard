from alerts.compliance_engine import ComplianceEngine, Severity

class TestStorageRules:
    def test_stg001_passes_when_https_only(self, storage_account_secure):
        results = ComplianceEngine().evaluate([storage_account_secure])
        r = next(x for x in results if x.rule_id == "STG-001")
        assert r.passed is True

    def test_stg001_fails_when_http_allowed(self, storage_account_insecure):
        results = ComplianceEngine().evaluate([storage_account_insecure])
        r = next(x for x in results if x.rule_id == "STG-001")
        assert r.passed is False

    def test_stg002_passes_when_public_access_disabled(self, storage_account_secure):
        results = ComplianceEngine().evaluate([storage_account_secure])
        r = next(x for x in results if x.rule_id == "STG-002")
        assert r.passed is True
        assert r.severity == Severity.CRITICAL

    def test_stg002_fails_when_public_access_enabled(self, storage_account_insecure):
        results = ComplianceEngine().evaluate([storage_account_insecure])
        r = next(x for x in results if x.rule_id == "STG-002")
        assert r.passed is False

    def test_stg003_passes_with_tls12(self, storage_account_secure):
        results = ComplianceEngine().evaluate([storage_account_secure])
        r = next(x for x in results if x.rule_id == "STG-003")
        assert r.passed is True

    def test_stg003_fails_with_tls10(self, storage_account_insecure):
        results = ComplianceEngine().evaluate([storage_account_insecure])
        r = next(x for x in results if x.rule_id == "STG-003")
        assert r.passed is False

class TestNSGRules:
    def test_nsg001_passes_with_no_wildcard(self, nsg_safe):
        results = ComplianceEngine().evaluate([nsg_safe])
        r = next(x for x in results if x.rule_id == "NSG-001")
        assert r.passed is True

    def test_nsg001_fails_with_wildcard_inbound(self, nsg_open):
        results = ComplianceEngine().evaluate([nsg_open])
        r = next(x for x in results if x.rule_id == "NSG-001")
        assert r.passed is False
        assert r.severity == Severity.CRITICAL

class TestGovernanceRules:
    def test_gov001_passes_with_environment_tag(self, storage_account_secure):
        results = ComplianceEngine().evaluate([storage_account_secure])
        r = next(x for x in results if x.rule_id == "GOV-001")
        assert r.passed is True

    def test_gov001_fails_without_environment_tag(self, storage_account_insecure):
        results = ComplianceEngine().evaluate([storage_account_insecure])
        r = next(x for x in results if x.rule_id == "GOV-001")
        assert r.passed is False

class TestComplianceScore:
    def test_perfect_score_with_secure_resources(self, storage_account_secure, nsg_safe):
        engine = ComplianceEngine()
        results = engine.evaluate([storage_account_secure, nsg_safe])
        score = engine.compute_score(results)
        assert score["score"] == 100

    def test_score_decreases_with_failures(self, storage_account_insecure):
        engine = ComplianceEngine()
        results = engine.evaluate([storage_account_insecure])
        score = engine.compute_score(results)
        assert score["score"] < 100
        assert score["failed"] > 0

    def test_empty_results_returns_100(self):
        score = ComplianceEngine().compute_score([])
        assert score["score"] == 100

    def test_passed_plus_failed_equals_total(self, storage_account_insecure, nsg_open):
        engine = ComplianceEngine()
        results = engine.evaluate([storage_account_insecure, nsg_open])
        score = engine.compute_score(results)
        assert score["passed"] + score["failed"] == score["total"]

    def test_score_between_0_and_100(self, storage_account_insecure, nsg_open):
        engine = ComplianceEngine()
        results = engine.evaluate([storage_account_insecure, nsg_open])
        score = engine.compute_score(results)
        assert 0 <= score["score"] <= 100

class TestVMRules:
    def test_vm001_passes_with_required_tags(self, virtual_machine_tagged):
        results = ComplianceEngine().evaluate([virtual_machine_tagged])
        r = next(x for x in results if x.rule_id == "VM-001")
        assert r.passed is True

    def test_vm001_fails_without_tags(self, virtual_machine_untagged):
        results = ComplianceEngine().evaluate([virtual_machine_untagged])
        r = next(x for x in results if x.rule_id == "VM-001")
        assert r.passed is False

    def test_vm002_fails_with_large_disk(self, virtual_machine_untagged):
        results = ComplianceEngine().evaluate([virtual_machine_untagged])
        r = next(x for x in results if x.rule_id == "VM-002")
        assert r.passed is False