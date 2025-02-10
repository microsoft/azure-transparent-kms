import pytest
from endpoints import setJwtValidationPolicy, removeJwtValidationPolicy

@pytest.mark.parametrize("setup_kms", [{"overRideDefaultSettingsPolicy": True}], indirect=True)
def test_set_jwtValidationPolicy(setup_kms):
    status_code, response = setJwtValidationPolicy(
        jwt_validation_policy={
            "issuer": "test-issuer",
            "validation_policy": {
                "iss": "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
                "aud": "https://management.azure.com/",
                "appid": "6b505410-70b8-46b6-a840-4403122e2a40",
                "appidacr": "2",
                "idp": "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
                "idtyp": "app",
                "oid": "049a48cd-7652-4159-82cf-7a2a42248b38",
                "sub": "049a48cd-7652-4159-82cf-7a2a42248b38",
                "tid": "72f988bf-86f1-41af-91ab-2d7cd011db47",
                "ver": "1.0",
                "xms_mirid": "/subscriptions/85c61f94-8912-4e82-900e-6ab44de9bdf8/resourcegroups/privacy-sandbox-dev/providers/Microsoft.ManagedIdentity/userAssignedIdentities/privacysandbox",
            },
        }
    )
    assert status_code == 200
    status_code, response = removeJwtValidationPolicy(issuer="test-issuer")
    assert status_code == 200

@pytest.mark.parametrize("setup_kms", [{"overRideDefaultSettingsPolicy": True}], indirect=True)
def test_removeJwtValidationPolicy(setup_kms):
    # Remove Test issue
    status_code, response = removeJwtValidationPolicy(issuer="test-issuer")
    assert status_code == 200


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-s"])
