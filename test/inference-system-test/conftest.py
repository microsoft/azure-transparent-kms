import json
import os
import subprocess
import pytest
from utils import apply_kms_constitution, deploy_app_code, trust_jwt_issuer
from endpoints import setKeyReleaseClaims, setJwtValidationPolicy

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
TEST_ENVIRONMENT = os.getenv("TEST_ENVIRONMENT", "ccf/sandbox_local")


@pytest.fixture()
def setup_kms():

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

    subprocess.run(
        f"scripts/{TEST_ENVIRONMENT}/down.sh",
    )

@pytest.fixture(scope="function", autouse=True)
def set_exclude_app_table_env():
    """Fixture to temporarily set EXCLUDE_APPTABLE_ENDPTS to 'true' for tests"""
    os.environ["EXCLUDE_APPTABLE_ENDPTS"] = "true"
    yield  # Run the test
    del os.environ["EXCLUDE_APPTABLE_ENDPTS"]  # Cleanup after test

# @pytest.fixture(scope="function", autouse=True)
# def setup_JWT_ReleaseClaims_Policy(setup_kms):
#     apply_kms_constitution()
#     trust_jwt_issuer(iss="http://Demo-jwt-issuer")
#     # Set JWT Validation Policy by calling SetJwtValidationPolicy endpt
#     status_code, response = setJwtValidationPolicy(
#         jwt_validation_policy={
#             "issuer": "http://Demo-jwt-issuer",
#             "validation_policy": {
#           "iss": "http://Demo-jwt-issuer",
#           "sub": "c0d8e9a7-6b8e-4e1f-9e4a-3b2c1d0f5a6b",
#           "name": "Cool caller"
#         },
#         }
#     )
#     # Setup KeyRelease Claims Default Policies for testing purpose
#     # note this should be overridden in test if needed
#     status_code, key_release_json = setKeyReleaseClaims(
#     type="claims", claims={
#           "x-ms-ver": ["1.0"],
#           "x-ms-azurevm-debuggersdisabled": True,
#           "x-ms-azurevm-osversion-major": [22, 23],
#           "x-ms-azurevm-os-provisioning.node-policy-identity.eventVersion": 1,
#           "x-ms-azurevm-os-provisioning.node-policy-identity.policyId": "openai-whisper",
#           "x-ms-azurevm-os-provisioning.node-policy-identity.signer": "8fe6e7a314b8695b21710cebf0265e8d7bbaabde26f431c407faf16fcbd6b924",
#           "x-ms-azurevm-os-provisioning.os-image-identity.diskId": "singularity.ubuntu-22.04",
#           "x-ms-azurevm-os-provisioning.os-image-identity.eventVersion": 1,
#           "x-ms-azurevm-os-provisioning.os-image-identity.signer": "f9cce5b7bdc2aaacfc4c78cb2b7515459aded8149287b74667bb2f178b0cf7b9"
#         })