import pytest
from endpoints import setKeyReleaseClaims, keyReleasePolicy

def test_keyReleaseClaim_add_remove(setup_kms, set_exclude_app_table_env):
    # Add claims by calling SetKeyRelease Endpoints
    status_code, key_release_json = setKeyReleaseClaims(
        type="add", claims={
          "x-ms-ver": ["1.0"],
          "x-ms-azurevm-debuggersdisabled": True,
          "x-ms-azurevm-osversion-major": [22, 23]
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
        type="remove", claims={"x-ms-attestation-type": "test-value"}
    )
    assert status_code == 200


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, '-s'])