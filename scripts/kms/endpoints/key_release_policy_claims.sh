#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

keyReleasePolicyClaims() {
    # Initialize variables
    local coseSigned=""

    # Parse arguments passed to the script
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --coseSigned)
                # Store pre-signed COSE bytes if provided
                coseSigned="$2"
                shift ;; # Move to the next argument
            *)
                # Handle unknown parameters and exit with an error
                echo "Unknown parameter: $1"
                exit 1 ;;
        esac
        shift # Move to the next argument
    done

    # Send the signed payload
    response=$(curl -X POST "${KMS_URL}/app/setKeyReleasePolicyClaims" \
        -H "Content-Type: application/cose" \
        --data-binary "@$coseSigned" \
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

# Invoke the function to execute the key release claims operation
keyReleasePolicyClaims "$@"