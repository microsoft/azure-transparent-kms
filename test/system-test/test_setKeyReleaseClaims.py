import pytest
from endpoints import setKeyReleaseClaims

def test_keyReleaseClaim_add(setup_kms):
    # Add claims
    status_code, key_release_json = setKeyReleaseClaims(
        type="add", claims={"x-ms-attestation-type": "test-value"}
    )
    assert status_code == 200


def test_keyReleaseClaim_remove(setup_kms):
    # Add claims
    status_code, key_release_json = setKeyReleaseClaims(
        type="remove", claims={"x-ms-attestation-type": "test-value"}
    )
    assert status_code == 200


def test_keyReleaseClaims_add(setup_kms):
    # Add claims
    status_code, key_release_json = setKeyReleaseClaims(
        type="add", claims={"x-ms-attestation-type": "test-value", "x-ms-compliance-status": "test-value"}
    )
    assert status_code == 200


def test_keyReleaseClaims_remove(setup_kms):
    # Add claims
    status_code, key_release_json = setKeyReleaseClaims(
        type="remove", claims={"x-ms-attestation-type": "test-value", "x-ms-compliance-status": "test-value"}
    )
    assert status_code == 200


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, '-s'])
