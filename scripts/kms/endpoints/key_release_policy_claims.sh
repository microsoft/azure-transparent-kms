#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

keyReleasePolicyClaims() {
    # Initialize variables
    local type=""
    local claims=""
    local signed_bytes=""

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
            --coseSigned)
                # Store pre-signed COSE bytes if provided
                signed_bytes="$2"
                shift ;; # Move to the next argument
            *)
                # Handle unknown parameters and exit with an error
                echo "Unknown parameter: $1"
                exit 1 ;;
        esac
        shift # Move to the next argument
    done

    # Capture both response body and status code
    if [ $coseSigned ]; then
        # Send the signed payload
        response=$(curl -X POST "${KMS_URL}/app/setKeyReleasePolicyClaims" \
            -H "Content-Type: application/cose" \
            --data-binary "@$file_path" \
            --cacert "${KMS_SERVICE_CERT_PATH}" \
            -s \
            -w "\n%{http_code}")
    else
        response=$(curl -s "$KMS_URL/app/setKeyReleasePolicyClaims" \
        --cacert "$KMS_SERVICE_CERT_PATH" \
        --cert "$KMS_USER_CERT_PATH" \
        --key "$KMS_USER_PRIVK_PATH" \
        -H "Content-Type: application/json" \
         -d "{\"claimType\": \"$type\", \"keyReleaseClaims\": $claims}" \
        -w '\n%{http_code}\n')
    fi

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