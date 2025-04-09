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

    response=$(curl -X POST "${KMS_URL}/app/setJwtValidationPolicy" \
        -H "Content-Type: application/cose" \
        --data-binary "@$policy" \
        --cacert "${KMS_SERVICE_CERT_PATH}" \
        -s \
        -w "\n%{http_code}")

    # Extract status code (last line)
    status_code=$(echo "$response" | tail -n1)

    # Extract JSON response (all lines except last)
    json_response=$(echo "$response" | sed '$d')

    # Ensure json_response is a valid JSON object, if empty default to {}
    if [[ -z "$json_response" ]]; then
        json_response="{}"
    fi

    # Return a proper JSON response
    echo "{\"status_code\": \"$status_code\", \"message\": \"$json_response\"}"
    echo $status_code
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


    response=$(curl -X POST "${KMS_URL}/app/removeJwtValidationPolicy" \
        -H "Content-Type: application/cose" \
        --data-binary "@$issuer" \
        --cacert "${KMS_SERVICE_CERT_PATH}" \
        -s \
        -w "\n%{http_code}")

    # Extract status code (last line)
    status_code=$(echo "$response" | tail -n1)

    # Extract JSON response (all lines except last)
    json_response=$(echo "$response" | sed '$d')

    # Ensure json_response is a valid JSON object, if empty default to {}
    if [[ -z "$json_response" ]]; then
        json_response="{}"
    fi

    # Return a proper JSON response
    echo "{\"status_code\": \"$status_code\", \"message\": \"$json_response\"}"
    echo $status_code

}

# Main script logic
main() {
    validate_env_vars

    # Default values
    action=""
    
    # Parse keyword arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --action)
                action="$2"
                shift 2
                ;;
            *)
                args+=("$1") # Store other args
                shift
                ;;
        esac
    done

    # Ensure action is provided
    if [[ -z "$action" ]]; then
        echo "Error: --action must be provided."
        usage
        exit 1
    fi

    case "$action" in
        "set")
            setJwtValidationPolicy "${args[@]}"
            ;;
        "remove")
            removeJwtValidationPolicy "${args[@]}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

# Execute main function with arguments
main "$@"