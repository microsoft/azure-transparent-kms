import pytest
from endpoints import setKeyRotationPolicy, getKeyRotationPolicy


def test_set_keyRotatePolicy(setup_kms):
    # Add claims
    status_code, key_release_json = setKeyRotationPolicy(
        key_rotation_policy={"rotation_interval_seconds": 30, "grace_period_seconds": 5}
    )
    assert status_code == 200


def test_keyReleaseClaim_remove(setup_kms):
    # Add claims
    status_code, key_rotation_policy = getKeyRotationPolicy()
    assert status_code == 200
    assert key_rotation_policy["rotation_interval_seconds"] == 30
    assert key_rotation_policy["grace_period_seconds"] == 5