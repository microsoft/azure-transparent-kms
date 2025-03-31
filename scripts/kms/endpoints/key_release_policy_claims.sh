#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Function to handle setting key release claims via the CCF API
keyReleasePolicyClaims() {

    # Parse arguments passed to the script
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --type)
                # Store the claim operation type (add/remove)
                type="$2"
                shift ;; # Move to the next argument
            --claims)
                # Store the JSON string containing the claims
                claims="$2"
                shift ;; # Move to the next argument
            *)
                # Handle unknown parameters and exit with an error
                echo "Unknown parameter: $1"
                exit 1 ;;
        esac
        shift # Move to the next argument
    done

    # Validate that both 'type' and 'claims' are provided
    if [[ -z "$type" || -z "$claims" ]]; then
        echo "Usage: keyReleasePolicyClaims.sh --type <add|remove> --claims <claims-json>"
        exit 1
    fi

    # Send a curl request to the CCF API endpoint to set the key release claims
    response=$(curl -s "$KMS_URL/app/setKeyReleasePolicyClaims" \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_USER_CERT_PATH" \
        --key "$KMS_USER_PRIVK_PATH" \
        -H "Content-Type: application/json" \
         -d "{\"claimType\": \"$type\", \"keyReleaseClaims\": $claims}" \
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

# Invoke the function to execute the key release claims operation
keyReleasePolicyClaims "$@"