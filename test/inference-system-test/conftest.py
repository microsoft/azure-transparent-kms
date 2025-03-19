import json
import os
import subprocess
import pytest
from utils import deploy_app_code, trust_jwt_issuer, cose_sign_payload
from endpoints import setKeyReleaseClaims, setJwtValidationPolicy

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
TEST_ENVIRONMENT = os.getenv("TEST_ENVIRONMENT", "ccf/sandbox_local")


@pytest.fixture()
def setup_kms():
    print
    # Setup the CCF backend and set the environment accordingly
    setup_vars = json.loads(subprocess.run(
            [f"scripts/{TEST_ENVIRONMENT}/up.sh", "--force-recreate"],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout.decode())
    os.environ.update(setup_vars)

    subprocess.run(
        ["make", "jwt-issuer-up"],
        cwd=REPO_ROOT,
        check=True,
    )
    os.environ["JWT_TOKEN_ISSUER_URL"] = "http://localhost:3000/token"
    os.environ["JWT_ISSUER"] = "http://Demo-jwt-issuer"

    deploy_app_code()

    yield

    subprocess.run(
        f"scripts/{TEST_ENVIRONMENT}/down.sh",
    )

# Fixture that does not need Governance MAA constitution
# This fixture mostly sets things up by calling newly added endpoints
# These endpoints update state in CCF Application tables
# This fixture is used by all system tests
@pytest.fixture(scope="function", autouse=True)
def setup_Default_JWT_ReleaseClaims_Policy(setup_kms, request):

    default_cose_signed = False
    default_jwt_issuer = "http://Demo-jwt-issuer"
    default_jwt_validation_policy = {
        "iss": default_jwt_issuer,
        "sub": "c0d8e9a7-6b8e-4e1f-9e4a-3b2c1d0f5a6b",
        "name": "Cool caller"
    }
    # Check if test overrides were provided
    overrides = getattr(request, "param", {})

    # Merge overrides with default values
    jwt_issuer = overrides.get("jwt_issuer", default_jwt_issuer)
    jwt_validation_policy = {**default_jwt_validation_policy, **overrides.get("jwt_validation_policy", {})}

    # Apply JWT Issuer
    # @yf23 this possibly should be a possible endpoint or a separate configuration
    trust_jwt_issuer(iss=jwt_issuer)

    # Set JWT Validation Policy
    # this calls added JWT Validation Policy Endpt
    status_code, _ = setJwtValidationPolicy(
        jwt_validation_policy={
            "issuer": jwt_issuer,
            "validation_policy": jwt_validation_policy
        }
    )
    assert status_code == 200

    # Default KeyRelease Claims Policy
    # This calls Set KeyReleaseClaims endpt
    default_key_release_claims = {
        "x-ms-ver": ["1.0"],
        "x-ms-azurevm-debuggersdisabled": True,
        "x-ms-azurevm-osversion-major": [22, 23],
        "x-ms-azurevm-os-provisioning.node-policy-identity.eventVersion": 1,
        "x-ms-azurevm-os-provisioning.node-policy-identity.policyId": "openai-whisper",
        # These values are not secrets, marking them as false positives
        "x-ms-azurevm-os-provisioning.node-policy-identity.signer": "8fe6e7a314b8695b21710cebf0265e8d7bbaabde26f431c407faf16fcbd6b924",  # pragma: allowlist secret
        "x-ms-azurevm-os-provisioning.os-image-identity.diskId": "singularity.ubuntu-22.04",
        "x-ms-azurevm-os-provisioning.os-image-identity.eventVersion": 1,
        "x-ms-azurevm-os-provisioning.os-image-identity.signer": "f9cce5b7bdc2aaacfc4c78cb2b7515459aded8149287b74667bb2f178b0cf7b9" # pragma: allowlist secret
    }

    # Merge KeyRelease Claims overrides if provided
    key_release_claims = {**default_key_release_claims, **overrides.get("key_release_claims", {})}
    cose_signed = overrides.get("cose_signed", default_cose_signed)
    if cose_signed:
        json_payload={"claimType": "claims", "claims": key_release_claims}
        # Cose Sign Payload
        cose_sign_payload("setKeyReleaseClaims", json_payload)

    # Apply KeyRelease Claims Policy
    status_code, _ = setKeyReleaseClaims(type="claims", claims=key_release_claims, cose_signed=cose_signed)
    assert status_code == 200