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
setKeyRotationPolicy() {
    local policy=""

    # Parse arguments for the 'set' operation
    if [[ "$1" == "--policy" && -n "$2" ]]; then
        policy="$2"
    else
        echo "Error: Missing or invalid key rotation policy."
        usage
    fi

    # Check for jq installation and install if missing
    if ! command -v jq > /dev/null 2>&1; then
        echo "'jq' is not installed. Attempting to install it now..."
        
        sudo apt-get update && sudo apt-get install -y jq

        # Verify if jq was successfully installed
        if ! command -v jq > /dev/null 2>&1; then
            echo "Error: 'jq' installation failed. Please install it manually."
            exit 1
        fi
        echo "'jq' installed successfully."
    fi

    # Validate JSON format
    if ! echo "$policy" | jq . > /dev/null 2>&1; then
        echo "Error: Invalid JSON provided for keyRotationPolicy."
        exit 1
    fi

    # Send a curl request to the CCF API endpoint
    response=$(curl "$KMS_URL/app/setKeyRotationPolicy" \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_MEMBER_CERT_PATH" \
        --key "$KMS_MEMBER_PRIVK_PATH" \
        -H "Content-Type: application/json" \
        -d "{\"key_rotation_policy\": $policy}" \
        -w '\n%{http_code}\n')

    # Extract status code from the response safely
    status_code=$(echo "$response" | tail -n1 | grep -oE '[0-9]+')

    if [[ -z "$status_code" ]]; then
        echo "Error: No valid response received from the server."
        exit 1
    fi

    if [[ "$status_code" -ne 200 ]]; then
        echo "Error: Failed to set key rotation policy. Status code: $status_code"
        exit 1
    fi

    echo "Key rotation policy set successfully."
}

# Function to handle getting key rotation policy via the CCF API
getKeyRotationPolicy() {
    # Send a curl request to the CCF API endpoint
    response=$(curl "$KMS_URL/app/getKeyRotationPolicy" \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_MEMBER_CERT_PATH" \
        --key "$KMS_MEMBER_PRIVK_PATH" \
        -H "Content-Type: application/json" \
        -w '\n%{http_code}\n')

    # Extract status code from the response safely
    status_code=$(echo "$response" | tail -n1 | grep -oE '[0-9]+')

    if [[ -z "$status_code" ]]; then
        echo "Error: No valid response received from the server."
        exit 1
    fi

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

    # Store operation in a variable
    operation="$1"
    shift

    case "$operation" in
        "set")
            setKeyRotationPolicy "$@"
            ;;
        "get")
            getKeyRotationPolicy
            ;;
        *)
            usage
            ;;
    esac
}

# Execute main function with arguments
main "$@"