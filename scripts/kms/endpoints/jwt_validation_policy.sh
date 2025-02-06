#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Function to display usage instructions
usage() {
    echo "Usage:"
    echo "  jwtValidationPolicy.sh set --policy <jwtValidationPolicy-json>"
    echo "  jwtValidationPolicy.sh remove --issuer <issuer>"
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

# Function to handle setting JWT validation policy via the CCF API
setJwtValidationPolicy() {
    local policy=""

    # Parse arguments for the 'set' operation
    if [[ "$1" == "--policy" && -n "$2" ]]; then
        policy="$2"
    else
        echo "Error: Missing or invalid JWT validation policy."
        usage
    fi

    # Check for jq installation and install if missing
    if ! command -v jq > /dev/null 2>&1; then
        echo "'jq' is not installed. Attempting to install it now..."
        
        sudo apt-get update && sudo apt-get install -y jq
        if ! command -v jq > /dev/null 2>&1; then
            echo "Error: 'jq' installation failed. Please install it manually."
            exit 1
        fi
        echo "'jq' installed successfully."
    fi

    # Validate JSON format
    if ! echo "$policy" | jq . > /dev/null 2>&1; then
        echo "Error: Invalid JSON provided for jwtValidationPolicy."
        exit 1
    fi

    # Send a curl request to the CCF API endpoint
    response=$(curl -s "$KMS_URL/app/setJwtValidationPolicy" \
        --cacert "$KMS_SERVICE_CERT_PATH" \
 auth_arg=(--cert $KMS_USER_CERT_PATH --key $KMS_USER_PRIVK_PATH)
        -H "Content-Type: application/json" \
        -d "{\"jwt_validation_policy\": $policy}" \
        -w '\n%{http_code}\n')

    # Extract status code from the response safely
    status_code=$(echo "$response" | tail -n1 | grep -oE '[0-9]+')

    if [[ -z "$status_code" ]]; then
        echo "Error: No valid response received from the server."
        exit 1
    fi

    if [[ "$status_code" -ne 200 ]]; then
        echo "Error: Failed to set JWT validation policy. Status code: $status_code"
        exit 1
    fi

    echo "JWT Validation policy set successfully."
}

# Function to remove JWT Validation policy via the CCF API
removeJwtValidationPolicy() {
    local issuer=""

    # Parse arguments for the 'remove' operation
    if [[ "$1" == "--issuer" && -n "$2" ]]; then
        issuer="$2"
    else
        echo "Error: Missing or invalid issuer."
        usage
    fi

    # Check if issuer is empty
    if [[ ${#issuer} -eq 0 ]]; then
        echo "Error: Issuer cannot be empty."
        exit 1
    fi

    # Send a curl request to the CCF API endpoint
    response=$(curl -s "$KMS_URL/app/removeJwtValidationPolicy" \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_MEMBER_CERT_PATH" \
        --key "$KMS_MEMBER_PRIVK_PATH" \
        -H "Content-Type: application/json" \
        -d "{\"issuer\": $issuer}" \
        -w '\n%{http_code}\n')

    # Extract status code from the response safely
    status_code=$(echo "$response" | tail -n1 | grep -oE '[0-9]+')

    if [[ -z "$status_code" ]]; then
        echo "Error: No valid response received from the server."
        exit 1
    fi

    if [[ "$status_code" -ne 200 ]]; then
        echo "Error: Failed to remove JWT Validation policy. Status code: $status_code"
        exit 1
    fi

    echo "Removed JWT Validation policy successfully."
}

# Main script logic
main() {
    validate_env_vars

    # Store operation in a variable
    operation="$1"
    shift

    case "$operation" in
        "set")
            setJwtValidationPolicy "$@"
            ;;
        "remove")
            removeJwtValidationPolicy "$@"
            ;;
        *)
            usage
            ;;
    esac
}

# Execute main function with arguments
main "$@"