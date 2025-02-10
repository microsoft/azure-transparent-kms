import os
import pytest
from endpoints import setSettingsPolicyApplicationEndpt, getSettingsPolicyApplicationEndpt

# LEDGER_TYPE = os.getenv("LEDGER_TYPE", "MCCF").lower()
# @pytest.mark.skipif(LEDGER_TYPE == "mccf", reason="MCCF does not support JWT validation policy endpoint")
# def test_settingsPolicy_with_no_policy(setup_kms):
#     status_code, settings_json = setSettingsPolicyApplicationEndpt()
#     assert status_code == 200
#     assert settings_json == {
#         "service": {
#             "name": "azure-privacy-sandbox-kms",
#             "description": "Key Management Service",
#             "version": "1.0.0",
#             "debug": False,
#         }
#     }

# LEDGER_TYPE = os.getenv("LEDGER_TYPE", "MCCF").lower()
# @pytest.mark.skipif(LEDGER_TYPE == "mccf", reason="MCCF does not support JWT validation policy endpoint")
# def test_settingsPolicy_with_no_auth(setup_kms):
#     status_code, settings_json = setSettingsPolicyApplicationEndpt(auth=None)
#     assert status_code == 401

@pytest.mark.parametrize("setup_kms", [{"overRideDefaultSettingsPolicy": True}], indirect=True)
def test_settingsPolicy_with_policy(setup_kms):

    policy = {
        "service": {
            "name": "custom-kms",
            "description": "Custom Key Management Service",
            "version": "2.1.0",
            "debug": True,
            "ledgerType": "acl",
        }
    }

    status_code, settings_json = setSettingsPolicyApplicationEndpt(settings_policy=policy)
    assert status_code == 200

if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-s"])
