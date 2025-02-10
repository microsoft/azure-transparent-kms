import os
import pytest
from endpoints import setKeyRotationPolicy, getKeyRotationPolicy

LEDGER_TYPE = os.getenv("LEDGER_TYPE", "MCCF").lower()
@pytest.mark.skipif(LEDGER_TYPE == "mccf", reason="MCCF does not support set Key Rotation policy endpoint")
def test_set_keyRotationPolicy(setup_kms):
    # Add claims
    status_code, key_release_json = setKeyRotationPolicy(
        key_rotation_policy={"rotation_interval_seconds": 30, "grace_period_seconds": 5}
    )
    assert status_code == 200

    # Check Rotation Policy
    status_code, key_rotation_policy = getKeyRotationPolicy()
    assert status_code == 200
    assert key_rotation_policy["message"]["rotation_interval_seconds"] == 30
    assert key_rotation_policy["message"]["grace_period_seconds"] == 5


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, '-s'])