#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Function to display usage instructions
usage() {
    echo "Usage:"
    echo "  settings_policy_app_endpt.sh set --policy <settings-json>"
    echo "  settings_policy_app_endpt.sh get"
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
setSettingsPolicy() {
    local policy=""

    # Parse arguments for the 'set' operation
    if [[ "$1" == "--policy" && -n "$2" ]]; then
        policy="$2"
    else
        echo "Error: Missing or invalid settings policy."
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
        echo "Error: Invalid JSON provided for setSettingsPolicy."
        exit 1
    fi

    # Send a curl request to the CCF API endpoint
    response=$(curl -s "$KMS_URL/app/setSettingsPolicy" \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_USER_CERT_PATH" \
        --key "$KMS_USER_PRIVK_PATH" \
        -H "Content-Type: application/json" \
        -d "{\"settings_policy\": $policy}" \
        -w '\n%{http_code}\n')

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

# Function to set Settings Policy
getSettingsPolicy() {
    # Send a curl request to the CCF API endpoint
    response=$(curl -s "$KMS_URL/app/settingsPolicy" \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_USER_CERT_PATH" \
        --key "$KMS_USER_PRIVK_PATH" \
        -w '\n%{http_code}\n')

    # Extract status code (last line)
    status_code=$(echo "$response" | tail -n1)

    # Extract JSON response (all lines except last)
    json_response=$(echo "$response" | sed '$d')

    # Ensure json_response is a valid JSON object, if empty default to {}
    if [[ -z "$json_response" ]]; then
        json_response="{}"
    fi

    # Return a proper JSON response
    echo "{\"status_code\": \"$status_code\", \"message\": "$json_response"}"
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
            setSettingsPolicy "${args[@]}"
            ;;
        "get")
            getSettingsPolicy "${args[@]}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

# Execute main function with arguments
main "$@"