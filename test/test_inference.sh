#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
set -euo pipefail

declare nodeAddress=""
declare certificate_dir=""
declare interactive=0

function usage {
    echo ""
    echo "Test this sample."
    echo ""
    echo "usage: ./test.sh --nodeAddress <IPADDRESS:PORT> --certificate_dir <workspace/sandbox_common> [--interactive]"
    echo ""
    echo "  --nodeAddress        string      The IP and port of the primary CCF node"
    echo "  --certificate_dir    string      The directory where the certificates are"
    echo "  --interactive        boolean     Optional. Run in Demo mode"
    echo ""
}

function failed {
    printf "💥 Script failed: %s\n\n" "$1"
    exit 1
}

# parse parameters
if [ $# -gt 5 ]; then
    usage
    exit 1
fi

while [ $# -gt 0 ]
do
    name="${1/--/}"
    name="${name/-/_}"
    case "--$name"  in
        --nodeAddress) nodeAddress="$2"; shift;;
        --certificate_dir) certificate_dir="$2"; shift;;
        --interactive) interactive=1;;
        --help) usage; exit 0;;
        --) shift;;
    esac
    shift;
done

# validate parameters
if [ -z "$nodeAddress" ]; then
    failed "You must supply --nodeAddress"
fi
if [ -z "$certificate_dir" ]; then
    failed "You must supply --certificate_dir"
fi

server="https://${nodeAddress}"

echo "📂 Directory for certificates: ${certificate_dir}"


only_status_code="-s -o /dev/null -w %{http_code}"

echo "💤 Waiting for the app frontend at ${server}..."
# Using the same way as https://github.com/microsoft/CCF/blob/1f26340dea89c06cf615cbd4ec1b32665840ef4e/tests/start_network.py#L94
# There is a side effect here in the case of the sandbox as it creates the 'workspace/sandbox_common' everytime
# it starts up. The following condition not only checks that this pem file has been created, it also checks it
# is valid. Don't be caught out by the folder existing from a previous run.
#while [ "200" != "$(curl "$server/app/commit" --cacert "${certificate_dir}/service_cert.pem" $only_status_code)" ]
#do
#    sleep 1
#done

# KMS test flow goes through TypeScript application located in ./test/e2e-test
echo "Running TypeScript flow..."

# adding read permission to .pem files so node application can have access
sudo chmod +r ${certificate_dir}/*.pem

# Calling npm command with the necessary variables
export SERVER=${server}
export CERTS_FOLDER=${certificate_dir}
export INTERACTIVE_MODE=${interactive}


echo "Setting JWT validation policy before running e2e test..."


issuer="http://Demo-jwt-issuer"
response=$(curl -sS "$server/app/setJwtValidationPolicy" \
    --cacert "/workspaces/azure-transparent-kms/workspace/sandbox_common/service_cert.pem" \
    --cert "/workspaces/azure-transparent-kms/workspace/sandbox_common/user0_cert.pem" \
    --key "/workspaces/azure-transparent-kms/workspace/sandbox_common/user0_privk.pem" \
    -H "Content-Type: application/json" \
    -d "{\"jwt_validation_policy\": {\"issuer\": \"http://Demo-jwt-issuer\", \"validation_policy\": {\"iss\": \"http://Demo-jwt-issuer\"}}}" \
    -w '\n%{http_code}')

# Split status and body
status_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n -1)

echo "JWT Policy Response Body: $body"
echo "Status Code : $status_code"

if [ "$status_code" -ne 200 ]; then
  echo "Failed to set JWT validation policy"
  echo "Response: $body"
  exit 1
fi


claims=$(cat <<EOF
{
  "claims": {
    "x-ms-ver": ["1.0"],
    "x-ms-azurevm-debuggersdisabled": true,
    "x-ms-azurevm-osversion-major": [22],
    "x-ms-azurevm-os-provisioning.node-policy-identity.eventVersion": 1,
    "x-ms-azurevm-os-provisioning.node-policy-identity.policyId": "openai-whisper",
    "x-ms-azurevm-os-provisioning.node-policy-identity.signer": "8fe6e7a314b8695b21710cebf0265e8d7bbaabde26f431c407faf16fcbd6b924",
    "x-ms-azurevm-os-provisioning.os-image-identity.diskId": "singularity.ubuntu-22.04",
    "x-ms-azurevm-os-provisioning.os-image-identity.eventVersion": 1,
    "x-ms-azurevm-os-provisioning.os-image-identity.signer": "f9cce5b7bdc2aaacfc4c78cb2b7515459aded8149287b74667bb2f178b0cf7b9"
  }
}
EOF
)

type="add"

response=$(curl -s "$server/app/setKeyReleasePolicyClaims" \
  --cacert "/workspaces/azure-transparent-kms/workspace/sandbox_common/service_cert.pem" \
  --cert "/workspaces/azure-transparent-kms/workspace/sandbox_common/user0_cert.pem" \
  --key "/workspaces/azure-transparent-kms/workspace/sandbox_common/user0_privk.pem" \
  -H "Content-Type: application/json" \
  -d "{\"claimType\": \"$type\", \"keyReleaseClaims\": $claims}" \
  -w '\n%{http_code}\n')

echo "Set KeyRelease Claims Policy Response: $response"

npm run e2e-inference-test

printf "\n\n🏁 Test Completed...\n"
exit 0
