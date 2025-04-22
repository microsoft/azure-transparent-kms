#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

set -e

# Default values
NETWORK_URL=""
PROPOSAL_FILE=""
CERTIFICATE_DIR=""
ENDPOINT="gov/proposals" # default if not overridden

usage() {
    echo "Usage: $0 --network-url <url> --proposal-file <file> --certificate_dir <dir> [--endpoint <endpoint>]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --network-url)
        NETWORK_URL="$2"
        shift
        shift
        ;;
        --proposal-file)
        PROPOSAL_FILE="$2"
        shift
        shift
        ;;
        --certificate_dir)
        CERTIFICATE_DIR="$2"
        shift
        shift
        ;;
        --endpoint)
        ENDPOINT="$2"
        shift
        shift
        ;;
        *)
        echo "Unknown option $1"
        usage
        ;;
    esac
done

# Validate required args
if [[ -z "$NETWORK_URL" || -z "$PROPOSAL_FILE" || -z "$CERTIFICATE_DIR" ]]; then
    echo "Missing required arguments."
    usage
fi

KMS_URL="$NETWORK_URL"
KMS_SERVICE_CERT_PATH="$CERTIFICATE_DIR/service_cert.pem"
KMS_MEMBER_CERT_PATH="$CERTIFICATE_DIR/member0_cert.pem"
KMS_MEMBER_PRIVK_PATH="$CERTIFICATE_DIR/member0_privk.pem"
KMS_USER_CERT_PATH="$CERTIFICATE_DIR/user0_cert.pem"
KMS_USER_PRIVK_PATH="$CERTIFICATE_DIR/user0_privk.pem"

echo "Proposing: $PROPOSAL_FILE"
echo "  to $KMS_URL/$ENDPOINT"
echo "    cert: $KMS_SERVICE_CERT_PATH"
echo "  as $KMS_USER_CERT_PATH"

ccf_cose_sign1 \
    --content "$PROPOSAL_FILE" \
    --signing-cert "${KMS_USER_CERT_PATH}" \
    --signing-key "${KMS_USER_PRIVK_PATH}" \
    --ccf-gov-msg-type proposal \
    --ccf-gov-msg-created_at "$(date -Is)" \
        | curl "$KMS_URL/$ENDPOINT" -k -H "Content-Type: application/cose" \
        --data-binary @- \
        -s \
        --cacert "$KMS_SERVICE_CERT_PATH" -w '\n' \

set +e
