#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Function to display usage instructions
usage() {
    echo "Usage:"
    echo "  keyRotationPolicy.sh set --keyRotationPolicy <keyRotationPolicy-json>"
    echo "  keyRotationPolicy.sh get"
    exit 1
}

# Validate required environment variables
validate_env_vars() {
    local missing=false
    for var in KMS_URL KMS_SERVICE_CERT_PATH KMS_MEMBER_CERT_PATH KMS_MEMBER_PRIVK_PATH; do
        if [[ -z "${!var}" ]]; then
            echo "Error: Missing required environment variable '$var'."
            missing=true
        fi
    done
    if [[ "$missing" == "true" ]]; then
        exit 1
    fi
}

# Function to handle setting key rotation policy via the CCF API
keyRotationPolicy() {
    local policy=""

    # Parse arguments for the 'set' operation
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --keyRotationPolicy)
                policy="$2"
                shift ;;
            *)
                echo "Unknown parameter: $1"
                usage ;;
        esac
        shift
    done

    # Validate that 'policy' is provided
    if [[ -z "$policy" ]]; then
        echo "Error: Missing key rotation policy."
        usage
    fi

    # Check for jq installation
    if ! command -v jq > /dev/null 2>&1; then
        echo "Error: 'jq' is not installed. Please install 'jq' to validate JSON input."
        exit 1
    fi

    # Validate JSON format
    if ! echo "$policy" | jq . > /dev/null 2>&1; then
        echo "Error: Invalid JSON provided for keyRotationPolicy."
        exit 1
    fi

    # Send a curl request to the CCF API endpoint
    response=$(curl $KMS_URL/app/setKeyRotationPolicy \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_MEMBER_CERT_PATH" \
        --key "$KMS_MEMBER_PRIVK_PATH" \
        -H "Content-Type: application/json" \
        -d "{\"key_rotation_policy\": $policy}" \
        -w '\n%{http_code}\n')

    # Extract status code from the response
    status_code=$(echo "$response" | tail -n1)

    if [[ "$status_code" -ne 200 ]]; then
        echo "Error: Failed to set key rotation policy. Status code: $status_code"
        exit 1
    fi

    echo "Key rotation policy set successfully."
}

# Function to handle getting key rotation policy via the CCF API
getKeyRotationPolicy() {
    # Send a curl request to the CCF API endpoint
    response=$(curl $KMS_URL/app/getKeyRotationPolicy \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_MEMBER_CERT_PATH" \
        --key "$KMS_MEMBER_PRIVK_PATH" \
        -H "Content-Type: application/json" \
        -w '\n%{http_code}\n')

    # Extract status code from the response
    status_code=$(echo "$response" | tail -n1)

    if [[ "$status_code" -ne 200 ]]; then
        echo "Error: Failed to retrieve key rotation policy. Status code: $status_code"
        exit 1
    fi

    # Print the policy from the response
    echo "Key rotation policy retrieved successfully:"
    echo "$response" | head -n -1
}

# Main script logic
main() {
    validate_env_vars

    if [[ "$1" == "set" ]]; then
        shift
        keyRotationPolicy "$@"
    elif [[ "$1" == "get" ]]; then
        getKeyRotationPolicy
    else
        usage
    fi
}

# Execute main function with arguments
main "$@"
