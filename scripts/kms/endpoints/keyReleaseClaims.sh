#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Function to handle setting key release claims via the CCF API
keyReleaseClaims() {

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
        echo "Usage: keyReleaseClaims.sh --type <add|remove> --claims <claims-json>"
        exit 1
    fi

    # Send a curl request to the CCF API endpoint to set the key release claims
    curl $KMS_URL/app/setKeyReleaseClaims \
        --cacert $KMS_SERVICE_CERT_PATH \ # Provide the service certificate for TLS
        --cert $KMS_MEMBER_CERT_PATH \    # Provide the member's client certificate
        --key $KMS_MEMBER_PRIVK_PATH \    # Provide the member's private key
        -H "Content-Type: application/json" \ # Specify the content type as JSON
        -d "{\"type\": \"$type\", \"claims\": $claims}" \ # Send the type and claims as JSON payload
        -w '\n%{http_code}\n'             # Output the HTTP status code at the end of the response
}

# Invoke the function to execute the key release claims operation
keyReleaseClaims "$@"
