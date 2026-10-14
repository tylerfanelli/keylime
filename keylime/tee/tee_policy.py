"""TEE attestation claims policy loading and validation."""

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Cache for loaded policy
_cached_policy: Optional[dict[str, Any]] = None
_cached_policy_path: Optional[str] = None


def validate_policy_structure(policy: dict[str, Any]) -> None:
    """
    Validate TEE policy JSON structure.

    Expected format:
    {
        "meta": {"version": "1.0"},
        "claims": {
            "claim_name": [allowed_value1, allowed_value2, ...],
            ...
        }
    }

    Raises:
        ValueError: If policy structure is invalid
    """
    if not isinstance(policy, dict):
        raise ValueError("TEE policy must be a JSON object")

    if "meta" not in policy:
        raise ValueError("TEE policy missing 'meta' section")

    if "version" not in policy["meta"]:
        raise ValueError("TEE policy meta section missing 'version' field")

    if "claims" not in policy:
        raise ValueError("TEE policy missing 'claims' section")

    if not isinstance(policy["claims"], dict):
        raise ValueError("TEE policy 'claims' must be an object")

    # Validate that each claim has a list of allowed values
    for claim_name, allowed_values in policy["claims"].items():
        if not isinstance(allowed_values, list):
            raise ValueError(f"TEE policy claim '{claim_name}' must have a list of allowed values")

        if len(allowed_values) == 0:
            raise ValueError(f"TEE policy claim '{claim_name}' has empty allowed values list")

    logger.debug("TEE policy structure validated successfully")


def load_tee_policy(policy_path: Optional[str]) -> Optional[dict[str, Any]]:
    """
    Load TEE policy from file with caching.

    Args:
        policy_path: Path to TEE policy JSON file, or None to skip loading

    Returns:
        Parsed policy dictionary, or None if path is not configured

    Raises:
        FileNotFoundError: If policy file doesn't exist
        json.JSONDecodeError: If policy file contains invalid JSON
        ValueError: If policy structure is invalid
    """
    global _cached_policy, _cached_policy_path

    # No policy configured
    if policy_path is None or policy_path == "":
        return None

    # Return cached policy if path hasn't changed
    if policy_path == _cached_policy_path and _cached_policy is not None:
        logger.debug("Returning cached TEE policy from %s", policy_path)
        return _cached_policy

    logger.info("Loading TEE policy from %s", policy_path)

    # Load from file
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
    except FileNotFoundError as e:
        logger.error("TEE policy file not found: %s", policy_path)
        raise
    except json.JSONDecodeError as e:
        logger.error("TEE policy file contains invalid JSON: %s", e)
        raise

    # Validate structure
    validate_policy_structure(policy)

    # Cache for future use
    _cached_policy = policy
    _cached_policy_path = policy_path

    logger.info("TEE policy loaded successfully from %s", policy_path)
    return policy


def clear_policy_cache() -> None:
    """Clear the cached TEE policy. Useful for testing."""
    global _cached_policy, _cached_policy_path
    _cached_policy = None
    _cached_policy_path = None
    logger.debug("TEE policy cache cleared")
