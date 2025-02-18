import pytest
from endpoints import key, refresh, setKeyReleaseClaims, setJwtValidationPolicy
from utils import apply_kms_constitution, apply_key_release_policy, trust_jwt_issuer, get_test_attestation, get_test_wrapping_key, trust_jwt_issuer_prop

@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
@pytest.mark.xfail(strict=True)
def test_no_keys(setup_kms):
    apply_kms_constitution()
    apply_key_release_policy()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 404

@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
def test_no_jwt_policy(setup_kms):
    apply_kms_constitution()
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 401
    
@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
def test_no_key_release_policy(setup_kms):
    apply_kms_constitution()
    trust_jwt_issuer()
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 500

@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
def test_with_keys_and_policy(setup_kms):
    apply_kms_constitution()
    # Set JWT Issuer
    trust_jwt_issuer(iss="http://Demo-jwt-issuer")
    status_code, response = setJwtValidationPolicy(
        jwt_validation_policy={
            "issuer": "http://Demo-jwt-issuer",
            "validation_policy": {
          "iss": "http://Demo-jwt-issuer",
          "sub": "c0d8e9a7-6b8e-4e1f-9e4a-3b2c1d0f5a6b",
          "name": "Cool caller"
        },
        }
    )
    assert status_code == 200
    # Set Key Release Claims
    status_code, key_release_json = setKeyReleaseClaims(
    type="claims", claims={
        "x-ms-ver": ["1.0"],
        "x-ms-azurevm-debuggersdisabled": True,
        "x-ms-azurevm-osversion-major": [22, 23]
    })
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 200

@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
def test_with_keys_and_policy_jwt_auth(setup_kms):
    apply_kms_constitution()
    apply_key_release_policy()
    trust_jwt_issuer()
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 200


def test_key_with_multiple(setup_kms):
    apply_kms_constitution()
    #Set JWT Issuer 
    trust_jwt_issuer(iss="http://Demo-jwt-issuer")
    # Set JWT Validation Policy by calling SetJwtValidationPolicy endpt
    status_code, response = setJwtValidationPolicy(
        jwt_validation_policy={
            "issuer": "http://Demo-jwt-issuer",
            "validation_policy": {
          "iss": "http://Demo-jwt-issuer",
          "sub": "c0d8e9a7-6b8e-4e1f-9e4a-3b2c1d0f5a6b",
          "name": "Cool caller"
        },
        }
    )
    assert status_code == 200
    #Set Key Release Claims by calling SetKeyRelease Claims Endpt
    status_code, key_release_json = setKeyReleaseClaims(
    type="claims", claims={
          "x-ms-ver": ["1.0"],
          "x-ms-azurevm-debuggersdisabled": True,
          "x-ms-azurevm-osversion-major": [22, 23],
          "x-ms-azurevm-os-provisioning.node-policy-identity.eventVersion": 1,
          "x-ms-azurevm-os-provisioning.node-policy-identity.policyId": "openai-whisper",
          "x-ms-azurevm-os-provisioning.node-policy-identity.signer": "8fe6e7a314b8695b21710cebf0265e8d7bbaabde26f431c407faf16fcbd6b924",
          "x-ms-azurevm-os-provisioning.os-image-identity.diskId": "singularity.ubuntu-22.04",
          "x-ms-azurevm-os-provisioning.os-image-identity.eventVersion": 1,
          "x-ms-azurevm-os-provisioning.os-image-identity.signer": "f9cce5b7bdc2aaacfc4c78cb2b7515459aded8149287b74667bb2f178b0cf7b9"
        })
    refresh()
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 200


# Test kid parameter
@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
def test_key_kid_not_present_with_other_keys(setup_kms):
    refresh()
    refresh()
    apply_kms_constitution()
    apply_key_release_policy()
    trust_jwt_issuer()
    while True:
        status_code, key_json = key(
            auth="jwt",
            kid="doesntexist"
        )
        if status_code != 202:
            break
    assert status_code == 400


@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
def test_key_kid_not_present_without_other_keys(setup_kms):
    apply_kms_constitution()
    apply_key_release_policy()
    trust_jwt_issuer()
    while True:
        status_code, key_json = key(
            auth="jwt",
            kid="doesntexist"
        )
        if status_code != 202:
            break
    assert status_code == 400

@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
def test_key_kid_present(setup_kms):
    apply_kms_constitution()
    apply_key_release_policy()
    trust_jwt_issuer()
    _, refresh_json = refresh()
    refresh()
    while True:
        status_code, key_json = key(
            auth="jwt",
            kid=refresh_json["id"]
        )
        if status_code != 202:
            break
    assert status_code == 200
    assert refresh_json["id"] == 1

@pytest.mark.skip(reason="Disabling this test as this test uses Governance actions")
def test_key_refresh_all_ids(setup_kms):
    apply_kms_constitution()
    apply_key_release_policy()
    trust_jwt_issuer()
    for _ in range(256):
        _, refresh_json = refresh()
    
    while True:
        status_code, key_json = key(
            auth="jwt",
            kid=refresh_json["id"]
        )
        if status_code != 202:
            break
    assert status_code == 200
    print(f"key_json: {key_json}")  # Debug print to see the contents of key_json

    assert key_json["kid"] == 0
    assert key_json["kid"] == refresh_json["id"]


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-s"])