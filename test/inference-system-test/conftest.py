import json
import os
import subprocess
import pytest
from utils import apply_kms_constitution, deploy_app_code, apply_settings_policy

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
TEST_ENVIRONMENT = os.getenv("TEST_ENVIRONMENT", "ccf/sandbox_local")


@pytest.fixture()
def setup_kms(request):

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

    params = request.param if isinstance(request.param, dict) else {}
    override_default_settings = params.get("overRideDefaultSettingsPolicy", False)

    # Used to Set LedgerType as ACL
    # newer application endpoints should be only accessed via ACL probably?
    if override_default_settings:
            apply_kms_constitution()

            # Apply a custom settings policy
            policy = {
                "service": {
                    "name": "custom-kms",
                    "description": "Custom Key Management Service",
                    "version": "2.0.0",
                    "debug": True,
                    "ledgerType": "acl"
                }
            }
            print("Applying custom settings policy {policy}")
            apply_settings_policy(policy)
        


    yield

    subprocess.run(
        f"scripts/{TEST_ENVIRONMENT}/down.sh",
    )
