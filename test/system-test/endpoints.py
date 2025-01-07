import json
import os
import subprocess

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))

def call_endpoint(endpoint, **kwargs):

    command = [f"scripts/kms/endpoints/{endpoint}.sh"]
    for k, v in kwargs.items():
        command.extend([f'--{k.replace("_", "-")}', str(v)])

    *response, status_code = subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.decode().splitlines()

    return (
        int(status_code),
        json.loads("".join(response) or '{}'),
    )


def heartbeat(**kwargs):
    return call_endpoint("heartbeat", **kwargs)


def key(**kwargs):
    return call_endpoint("key", **kwargs)


def listpubkeys(**kwargs):
    return call_endpoint("listpubkeys", **kwargs)


def pubkey(**kwargs):
    return call_endpoint("pubkey", **kwargs)


def refresh(**kwargs):
    return call_endpoint("refresh", **kwargs)


def keyReleasePolicy(**kwargs):
    return call_endpoint("keyReleasePolicy", **kwargs)


def settingsPolicy(**kwargs):
    return call_endpoint("settingsPolicy", **kwargs)

def setKeyReleaseClaims(type: str, claims: dict):
    if not type or not claims:
        raise ValueError("Both 'type' and 'claims' are required.")
    
    claims_json = json.dumps(claims)  # Convert the claims dictionary to a JSON string
    return call_endpoint("keyReleaseClaims", type=type, claims=claims_json)

def setKeyRotationPolicy(key_rotation_policy: dict):
    if not key_rotation_policy:
        raise ValueError("'key_rotation_policy' is required.")
    
    key_rotation_policy_json = json.dumps(key_rotation_policy)  # Convert the claims dictionary to a JSON string
    return call_endpoint("keyRotationPolicy", key_rotation_policy=key_rotation_policy_json)


def getKeyRotationPolicy():
    return call_endpoint("getKeyRotationPolicy")