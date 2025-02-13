import pytest
from endpoints import setKeyReleaseClaims

def test_keyReleaseClaim_add_remove(setup_kms, set_exclude_app_table_env):
    # Add claims
    status_code, key_release_json = setKeyReleaseClaims(
        type="add", claims={"x-ms-attestation-type": "test-value"}
    )
    assert status_code == 200
    # Remove Claims
    status_code, key_release_json = setKeyReleaseClaims(
        type="remove", claims={"x-ms-attestation-type": "test-value"}
    )
    assert status_code == 200


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, '-s'])