import json
import os
import subprocess
import pytest
from utils import deploy_app_code

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

    if os.getenv("EXCLUDE_APPTABLE_ENDPTS") == "true":
        deploy_app_code()
    else:
        deploy_app_code(include_apptable_endpts=True)

    yield

    subprocess.run(
        f"scripts/{TEST_ENVIRONMENT}/down.sh",
    )

@pytest.fixture(scope="function", autouse=True)
def set_exclude_app_table_env():
    """Fixture to temporarily set EXCLUDE_APPTABLE_ENDPTS to 'true' for tests"""
    os.environ["EXCLUDE_APPTABLE_ENDPTS"] = "true"
    yield  # Run the test
    del os.environ["EXCLUDE_APPTABLE_ENDPTS"]  # Cleanup after test