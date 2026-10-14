"""Unit tests for SNP claim validation against TEE policy."""

import json
import unittest

from keylime.failure import Component, Failure
from keylime.tee.snp import validate_claims_against_policy


class TestSNPClaimValidation(unittest.TestCase):
    """Test SNP claim validation against TEE policy."""

    def test_validate_claims_matching_policy(self):
        """Test that matching claims pass validation."""
        claims = {
            "reported_tcb_snp": 8,
            "policy_debug_allowed": False,
            "platform_smt_enabled": False,
        }

        policy = {
            "claims": {
                "reported_tcb_snp": [8, 9, 10],
                "policy_debug_allowed": [False],
                "platform_smt_enabled": [False, True],
            }
        }

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        self.assertTrue(result)
        self.assertEqual(len(failure.events), 0)

    def test_validate_claims_policy_violation(self):
        """Test that non-matching claims fail validation."""
        claims = {
            "reported_tcb_snp": 7,  # Not in allowlist
            "policy_debug_allowed": False,
        }

        policy = {"claims": {"reported_tcb_snp": [8, 9, 10], "policy_debug_allowed": [False]}}

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        self.assertFalse(result)
        self.assertEqual(len(failure.events), 1)
        self.assertEqual(failure.events[0].event_id, "tee_attestation.policy_violation")
        context = json.loads(failure.events[0].context)
        self.assertIn("reported_tcb_snp", context["claim"])

    def test_validate_claims_multiple_allowed_values(self):
        """Test validation with multiple allowed values per claim."""
        claims = {
            "reported_tcb_snp": 9,  # Second value in allowlist
            "policy_smt_allowed": True,  # Second value in allowlist
        }

        policy = {"claims": {"reported_tcb_snp": [8, 9, 10], "policy_smt_allowed": [False, True]}}

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        self.assertTrue(result)
        self.assertEqual(len(failure.events), 0)

    def test_validate_claims_unknown_claim_in_policy(self):
        """Test that unknown claims in policy are ignored (forward compatibility)."""
        claims = {"reported_tcb_snp": 8}

        policy = {
            "claims": {
                "reported_tcb_snp": [8, 9, 10],
                "future_claim_name": [123],  # Not in attestation claims
            }
        }

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        # Should pass - unknown claims in policy are ignored
        self.assertTrue(result)
        self.assertEqual(len(failure.events), 0)

    def test_validate_claims_unspecified_claim(self):
        """Test that claims not in policy are not validated (permissive)."""
        claims = {
            "reported_tcb_snp": 8,
            "policy_debug_allowed": True,  # Not checked by policy
            "platform_smt_enabled": True,  # Not checked by policy
        }

        policy = {"claims": {"reported_tcb_snp": [8, 9, 10]}}  # Only checks this one claim

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        # Should pass - only reported_tcb_snp is checked
        self.assertTrue(result)
        self.assertEqual(len(failure.events), 0)

    def test_validate_claims_missing_claims_section(self):
        """Test that policy without claims section fails."""
        claims = {"reported_tcb_snp": 8}

        policy = {"meta": {"version": "1.0"}}  # No claims section

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        self.assertFalse(result)
        self.assertEqual(len(failure.events), 1)
        self.assertEqual(failure.events[0].event_id, "tee_attestation.invalid_policy")
        context = json.loads(failure.events[0].context)
        self.assertIn("missing 'claims' section", context["message"])

    def test_validate_claims_boolean_values(self):
        """Test validation of boolean claim values."""
        claims = {
            "policy_debug_allowed": False,
            "policy_smt_allowed": True,
            "platform_smt_enabled": False,
        }

        policy = {
            "claims": {
                "policy_debug_allowed": [False],
                "policy_smt_allowed": [True, False],
                "platform_smt_enabled": [False],
            }
        }

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        self.assertTrue(result)
        self.assertEqual(len(failure.events), 0)

    def test_validate_claims_integer_values(self):
        """Test validation of integer claim values."""
        claims = {
            "reported_tcb_bootloader": 2,
            "reported_tcb_tee": 0,
            "reported_tcb_snp": 10,
            "reported_tcb_microcode": 95,
        }

        policy = {
            "claims": {
                "reported_tcb_bootloader": [2, 3],
                "reported_tcb_tee": [0],
                "reported_tcb_snp": [8, 9, 10],
                "reported_tcb_microcode": [93, 94, 95],
            }
        }

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        self.assertTrue(result)
        self.assertEqual(len(failure.events), 0)

    def test_validate_claims_list_values(self):
        """Test validation of list claim values (e.g., measurement)."""
        # Measurement is a 48-byte list
        measurement = [0] * 48
        claims = {"measurement": measurement}

        policy = {"claims": {"measurement": [measurement, [1] * 48]}}  # Two allowed measurements

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        self.assertTrue(result)
        self.assertEqual(len(failure.events), 0)

    def test_validate_claims_list_values_no_match(self):
        """Test that non-matching list values fail validation."""
        measurement = [0] * 48
        different_measurement = [1] * 48
        claims = {"measurement": measurement}

        policy = {
            "claims": {"measurement": [different_measurement, [2] * 48]}  # Neither matches
        }

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        self.assertFalse(result)
        self.assertEqual(len(failure.events), 1)
        self.assertEqual(failure.events[0].event_id, "tee_attestation.policy_violation")

    def test_validate_empty_policy(self):
        """Test validation with empty claims in policy (permissive)."""
        claims = {
            "reported_tcb_snp": 8,
            "policy_debug_allowed": True,
        }

        policy = {"claims": {}}  # No claims to check

        failure = Failure(Component.TEE)
        result = validate_claims_against_policy(claims, policy, failure)

        # Should pass - no claims to validate
        self.assertTrue(result)
        self.assertEqual(len(failure.events), 0)


if __name__ == "__main__":
    unittest.main()
