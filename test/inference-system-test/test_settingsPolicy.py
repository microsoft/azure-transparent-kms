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
        }
    }

    status_code, settings_json = setSettingsPolicy(settings_policy=policy)
    assert status_code == 200

    status_code, settings_json = settingsPolicy()
    assert status_code == 200
    assert settings_json["service"]["name"] == "custom-kms"
    assert settings_json["service"]["description"] == "Custom Key Management Service"
    assert settings_json["service"]["version"] == "2.1.0"
    assert settings_json["service"]["debug"] == True

if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-s"])