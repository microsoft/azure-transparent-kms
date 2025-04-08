import pytest
from endpoints import setKeyReleaseClaims, keyReleasePolicy

@pytest.mark.parametrize(
    "setup_Default_JWT_ReleaseClaims_Policy",
    [{
        "cose_signed": True,
    }],
    indirect=True
)
def test_keyReleaseClaim_add_remove(setup_kms):
    # Add claims by calling SetKeyRelease Endpoints

    status_code, key_release_json = setKeyReleaseClaims(
        type="add",
        claims={
            "claims": {
                "x-ms-ver": ["1.0"],
                "x-ms-azurevm-debuggersdisabled": True,
                "x-ms-azurevm-osversion-major": [22, 23]
            }
        }
    )
    assert status_code == 200
    status_code, key_release_json = keyReleasePolicy()
    assert status_code == 200
    assert key_release_json["claims"]["x-ms-ver"] == ["1.0"]
    assert key_release_json["claims"]["x-ms-azurevm-debuggersdisabled"] == True
    assert key_release_json["claims"]["x-ms-azurevm-osversion-major"] == [22, 23]

    # Remove Claims
    status_code, key_release_json = setKeyReleaseClaims(
        type="remove",
        claims={
            "claims": {
                "x-ms-attestation-type": "test-value"
            }
        }
    )
    assert status_code == 200

@pytest.mark.parametrize(
    "setup_Default_JWT_ReleaseClaims_Policy",
    [{
        "cose_signed": True,
    }],
    indirect=True
)
def test_keyReleaseClaim_add_remove_with_operators(setup_kms):
    # Add claims by calling SetKeyRelease Endpoints
    status_code, key_release_json = setKeyReleaseClaims(
        type="add",
        claims={
            "claims": {
                "x-ms-ver": ["1.0"],
                "x-ms-azurevm-debuggersdisabled": True,
                "x-ms-azurevm-osversion-major": [22, 23]
            },
            "gte": {
                "x-ms-ver": "2"
            },
            "gt": {
                "x-ms-ver": "1"
            }
        }
    )
    assert status_code == 200

    status_code, key_release_json = keyReleasePolicy()
    assert status_code == 200

    assert key_release_json["claims"]["x-ms-ver"] == ["1.0"]
    assert key_release_json["claims"]["x-ms-azurevm-debuggersdisabled"] == True
    assert key_release_json["claims"]["x-ms-azurevm-osversion-major"] == [22, 23]

    # Validate operator claims
    assert key_release_json["gte"]["x-ms-ver"] == "2"
    assert key_release_json["gt"]["x-ms-ver"] == "1"

    # Remove claim
    status_code, key_release_json = setKeyReleaseClaims(
        type="remove",
        claims={
            "claims": {
                "x-ms-attestation-type": "test-value"
            },
            "gte": {
                "x-ms-ver": "2"
            },
            "gt": {
                "x-ms-ver": "1"
            }
        }
    )
    assert status_code == 200

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, '-s'])