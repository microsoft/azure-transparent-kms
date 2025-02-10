import os
import pytest
from endpoints import setKeyReleaseClaims

LEDGER_TYPE = os.getenv("LEDGER_TYPE", "MCCF").lower()
@pytest.mark.skipif(LEDGER_TYPE == "mccf", reason="MCCF does not support Key Release Claims policy set endpoint")
def test_keyReleaseClaim_add_remove(setup_kms):
    # Add claims
    status_code, key_release_json = setKeyReleaseClaims(
        type="add", claims={"x-ms-attestation-type": "test-value"}
    )
    assert status_code == 200
    status_code, key_release_json = setKeyReleaseClaims(
        type="remove", claims={"x-ms-attestation-type": "test-value"}
    )
    assert status_code == 200


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, '-s'])