"""Unit tests for TEE policy loading and validation."""

import json
import os
import tempfile
import unittest

from keylime.tee import tee_policy


class TestTEEPolicy(unittest.TestCase):
    """Test TEE policy loading and validation."""

    def setUp(self):
        """Set up test fixtures."""
        # Clear cache before each test
        tee_policy.clear_policy_cache()

        # Get test data directory
        test_dir = os.path.dirname(os.path.abspath(__file__))
        self.data_dir = os.path.join(test_dir, "data")

    def test_load_valid_policy(self):
        """Test loading a valid TEE policy from file."""
        policy_path = os.path.join(self.data_dir, "tee-policy-valid.json")
        policy = tee_policy.load_tee_policy(policy_path)

        self.assertIsNotNone(policy)
        self.assertIn("meta", policy)
        self.assertIn("claims", policy)
        self.assertEqual(policy["meta"]["version"], "1.0")
        self.assertIsInstance(policy["claims"], dict)

    def test_load_minimal_policy(self):
        """Test loading a minimal valid policy."""
        policy_path = os.path.join(self.data_dir, "tee-policy-minimal.json")
        policy = tee_policy.load_tee_policy(policy_path)

        self.assertIsNotNone(policy)
        self.assertIn("claims", policy)
        self.assertEqual(len(policy["claims"]), 1)
        self.assertIn("policy_debug_allowed", policy["claims"])

    def test_load_invalid_policy_missing_meta(self):
        """Test that loading invalid policy (missing meta) raises ValueError."""
        policy_path = os.path.join(self.data_dir, "tee-policy-invalid.json")

        with self.assertRaises(ValueError) as cm:
            tee_policy.load_tee_policy(policy_path)

        self.assertIn("missing 'meta' section", str(cm.exception))

    def test_load_nonexistent_file(self):
        """Test that loading nonexistent file raises FileNotFoundError."""
        policy_path = "/tmp/nonexistent-tee-policy.json"

        with self.assertRaises(FileNotFoundError):
            tee_policy.load_tee_policy(policy_path)

    def test_load_invalid_json(self):
        """Test that loading invalid JSON raises JSONDecodeError."""
        # Create temporary file with invalid JSON
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json content")
            temp_path = f.name

        try:
            with self.assertRaises(json.JSONDecodeError):
                tee_policy.load_tee_policy(temp_path)
        finally:
            os.unlink(temp_path)

    def test_policy_caching(self):
        """Test that policy is cached after first load."""
        policy_path = os.path.join(self.data_dir, "tee-policy-valid.json")

        # First load
        policy1 = tee_policy.load_tee_policy(policy_path)

        # Second load should return cached version
        policy2 = tee_policy.load_tee_policy(policy_path)

        # Should be the same object (cached)
        self.assertIs(policy1, policy2)

    def test_cache_cleared_on_different_path(self):
        """Test that cache is not used for different policy path."""
        policy_path1 = os.path.join(self.data_dir, "tee-policy-valid.json")
        policy_path2 = os.path.join(self.data_dir, "tee-policy-minimal.json")

        policy1 = tee_policy.load_tee_policy(policy_path1)
        policy2 = tee_policy.load_tee_policy(policy_path2)

        # Should be different objects (different files)
        self.assertIsNot(policy1, policy2)
        self.assertNotEqual(len(policy1["claims"]), len(policy2["claims"]))

    def test_load_none_path(self):
        """Test that None path returns None."""
        policy = tee_policy.load_tee_policy(None)
        self.assertIsNone(policy)

    def test_load_empty_path(self):
        """Test that empty path returns None."""
        policy = tee_policy.load_tee_policy("")
        self.assertIsNone(policy)

    def test_validate_policy_structure_valid(self):
        """Test validation of valid policy structure."""
        valid_policy = {
            "meta": {"version": "1.0"},
            "claims": {"policy_debug_allowed": [False]},
        }

        # Should not raise
        tee_policy.validate_policy_structure(valid_policy)

    def test_validate_policy_structure_missing_claims(self):
        """Test validation fails for policy missing claims section."""
        invalid_policy = {"meta": {"version": "1.0"}}

        with self.assertRaises(ValueError) as cm:
            tee_policy.validate_policy_structure(invalid_policy)

        self.assertIn("missing 'claims' section", str(cm.exception))

    def test_validate_policy_structure_missing_version(self):
        """Test validation fails for policy missing version in meta."""
        invalid_policy = {"meta": {}, "claims": {}}

        with self.assertRaises(ValueError) as cm:
            tee_policy.validate_policy_structure(invalid_policy)

        self.assertIn("missing 'version' field", str(cm.exception))

    def test_validate_policy_structure_claims_not_dict(self):
        """Test validation fails if claims is not a dict."""
        invalid_policy = {"meta": {"version": "1.0"}, "claims": []}

        with self.assertRaises(ValueError) as cm:
            tee_policy.validate_policy_structure(invalid_policy)

        self.assertIn("must be an object", str(cm.exception))

    def test_validate_policy_structure_claim_value_not_list(self):
        """Test validation fails if claim value is not a list."""
        invalid_policy = {
            "meta": {"version": "1.0"},
            "claims": {"policy_debug_allowed": False},  # Should be [False]
        }

        with self.assertRaises(ValueError) as cm:
            tee_policy.validate_policy_structure(invalid_policy)

        self.assertIn("must have a list of allowed values", str(cm.exception))

    def test_validate_policy_structure_empty_allowed_values(self):
        """Test validation fails if claim has empty allowed values list."""
        invalid_policy = {
            "meta": {"version": "1.0"},
            "claims": {"policy_debug_allowed": []},  # Empty list
        }

        with self.assertRaises(ValueError) as cm:
            tee_policy.validate_policy_structure(invalid_policy)

        self.assertIn("has empty allowed values list", str(cm.exception))

    def test_clear_policy_cache(self):
        """Test that cache clearing works."""
        policy_path = os.path.join(self.data_dir, "tee-policy-valid.json")

        # Load policy
        policy1 = tee_policy.load_tee_policy(policy_path)

        # Clear cache
        tee_policy.clear_policy_cache()

        # Load again - should be different object
        policy2 = tee_policy.load_tee_policy(policy_path)

        # Objects should be different (not cached)
        self.assertIsNot(policy1, policy2)
        # But content should be the same
        self.assertEqual(policy1, policy2)


if __name__ == "__main__":
    unittest.main()
