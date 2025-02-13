import os
import pytest
from endpoints import setSettingsPolicy, settingsPolicy


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

    status_code, settings_json = setSettingsPolicy(settings_policy=policy)
    assert status_code == 200

    status_code, settings_json = settingsPolicy()
    assert status_code == 200

if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-s"])