import json
import os
import subprocess

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))

import subprocess
import json
from utils import cose_sign_payload

def call_endpoint(endpoint, **kwargs):

    command = [f"scripts/kms/endpoints/{endpoint}.sh"]
    for k, v in kwargs.items():
        if isinstance(v, dict):
            v = json.dumps(v)
        command.extend([f'--{k.replace("_", "-")}', str(v)])

    *response, status_code = (
        subprocess.run(
            command,
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        )
        .stdout.decode()
        .splitlines()
    )

    return (
        int(status_code),
        json.loads("".join(response) or "{}"),
    )


def heartbeat(**kwargs):
    return call_endpoint("heartbeat", **kwargs)


def key(**kwargs):
    return call_endpoint("key", **kwargs)


def listpubkeys(**kwargs):
    return call_endpoint("listpubkeys", **kwargs)


def refresh(**kwargs):
    return call_endpoint("refresh", **kwargs)


def keyReleasePolicy(**kwargs):
    return call_endpoint("keyReleasePolicy", **kwargs)


def settingsPolicy(**kwargs):
    return call_endpoint("settings_policy", action="get", **kwargs)


def setSettingsPolicy(settings_policy: dict):
    if not settings_policy:
        raise ValueError("'settings_policy' is required.")

    set_settings_policy_json = json.dumps(
        settings_policy
    )  # Convert the claims dictionary to a JSON string
    return call_endpoint(
        "settings_policy", action="set", policy=set_settings_policy_json
    )

def auth(**kwargs):
    return call_endpoint("auth", **kwargs)


def setKeyReleaseClaims(type: str, claims: dict, cose_signed: bool = False):
    if not type or not claims:
        raise ValueError("Both 'type' and 'claims' are required.")
    
    json_payload={"claimType": type, "keyReleaseClaims": claims}
    cose_signed_file = cose_sign_payload("setKeyReleaseClaims", json_payload)
    
    return call_endpoint("key_release_policy_claims", coseSigned=cose_signed_file)


def setKeyRotationPolicy(key_rotation_policy: dict):
    if not key_rotation_policy:
        raise ValueError("'key_rotation_policy' is required.")

    json_payload={"key_rotation_policy": key_rotation_policy}
    cose_signed_file = cose_sign_payload("setKeyRotationPolicy", json_payload)

    return call_endpoint("key_rotation_policy", action="set", policy=cose_signed_file)


def getKeyRotationPolicy():
    return call_endpoint("key_rotation_policy", action="get")


def setJwtValidationPolicy(jwt_validation_policy: dict):
    if not jwt_validation_policy:
        raise ValueError("'jwt_validation_policy' is required.")
    
    json_payload={"jwt_validation_policy": jwt_validation_policy}
    cose_signed_policy = cose_sign_payload("setJwtValidationPolicy", json_payload)
    
    return call_endpoint(
        "jwt_validation_policy", action="set", policy=cose_signed_policy
    )

def removeJwtValidationPolicy(issuer: str):
    json_payload={"issuer": issuer}
    cose_signed_policy = cose_sign_payload("removeJwtValidationPolicy", json_payload)
    
    return call_endpoint("jwt_validation_policy", action="remove", issuer=cose_signed_policy)