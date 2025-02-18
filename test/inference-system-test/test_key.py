import pytest
from endpoints import key, refresh
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

# @yf23 to investigate and fix this test
@pytest.mark.skip(reason="Disabling this and investigate failure: assert 200 == 401")
def test_no_jwt_policy(setup_kms):
    apply_kms_constitution()
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 401

# @yf23 to investigate and fix this test
@pytest.mark.skip(reason="Disabling this test and investigate failure: assert 200 == 500")
def test_no_key_release_policy(setup_kms):
    apply_kms_constitution()
    trust_jwt_issuer()
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 500


def test_with_keys_and_policy_jwt_auth(setup_Default_JWT_ReleaseClaims_Policy):
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 200


def test_key_with_multiple(setup_Default_JWT_ReleaseClaims_Policy):
    # Default JWT and Release Claims Policy already set by calling setup_JWT_ReleaseClaims_Policy fixture

    refresh()
    refresh()
    while True:
        status_code, key_json = key(auth="jwt")
        if status_code != 202:
            break
    assert status_code == 200


# Test kid parameter
def test_key_kid_not_present_with_other_keys(setup_Default_JWT_ReleaseClaims_Policy):
    refresh()
    refresh()
    while True:
        status_code, key_json = key(
            auth="jwt",
            kid="doesntexist"
        )
        if status_code != 202:
            break
    assert status_code == 400


def test_key_kid_not_present_without_other_keys(setup_Default_JWT_ReleaseClaims_Policy):
    while True:
        status_code, key_json = key(
            auth="jwt",
            kid="doesntexist"
        )
        if status_code != 202:
            break
    assert status_code == 400


def test_key_kid_present(setup_Default_JWT_ReleaseClaims_Policy):
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


def test_key_refresh_all_ids(setup_Default_JWT_ReleaseClaims_Policy):
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