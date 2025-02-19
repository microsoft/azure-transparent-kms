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

    status_code, output_json = settingsPolicy()
    assert status_code == 200
    assert output_json["message"]["service"]["name"] == "custom-kms"
    assert output_json["message"]["service"]["description"] == "Custom Key Management Service"
    assert output_json["message"]["service"]["version"] == "2.1.0"
    assert output_json["message"]["service"]["debug"] == True

if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-s"])