# #!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Function to sign a JSON payload using COSE signing
sign_payload() {
    local key_path="$1"
    local cert_path="$2"
    local msg_type="$3"
    local json_payload="$4"
    local skip_reqd_header="$5"
    
    # Log info
    echo "INFO: Signing payload with msg_type: $msg_type"
    
    # Check if files exist
    if [ ! -f "$key_path" ]; then
        echo "ERROR: Key file not found: $key_path" >&2
        return 1
    fi
    
    if [ ! -f "$cert_path" ]; then
        echo "ERROR: Certificate file not found: $cert_path" >&2
        return 1
    fi
    
    # Read key and cert
    local key=$(cat "$key_path")
    if [ -z "$key" ]; then
        echo "ERROR: Key file is empty or improperly formatted." >&2
        return 1
    fi
    
    local cert=$(cat "$cert_path")
    if [ -z "$cert" ]; then
        echo "ERROR: Cert file is empty or improperly formatted." >&2
        return 1
    fi
    
    # Prepare header parameters
    local header_params=""
    if [ "$skip_reqd_header" = "true" ]; then
        header_params="--header-param acl.msg.type=\"$msg_type\""
    else
        header_params="--header-param acl.msg.type=\"$msg_type\" --header-param acl.msg.created_at=\"$(date +%s)\""
    fi
    
    # Use eval to properly handle the header parameters
    eval "user_cose_sign1 \
        --content '$json_payload' \
        --signing-key '$key_path' \
        --signing-cert '$cert_path' \
        $header_params"
}


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
            --cosePayload)
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

    echo $signed_bytes
    # If signed bytes aren't provided, validate that both 'type' and 'claims' are provided
    if [[ -z "$signed_bytes" ]]; then
        if [[ -z "$type" || -z "$claims" ]]; then
            echo "Usage: keyReleasePolicyClaims.sh --type <add|remove> --claims <claims-json> [--signed-bytes <cose-signed-bytes>]"
            exit 1
        fi
        
        # Create JSON payload and sign it
        json_payload="{\"claimType\": \"$type\", \"claims\": $claims}"
        signed_payload=$(sign_payload "$KMS_USER_PRIVK_PATH" "$KMS_USER_CERT_PATH" "setKeyreleaseClaims" "$json_payload" "false")
    else
        # Use the provided signed bytes
        signed_payload="$signed_bytes"
    fi
    
    # Send the signed payload
    response=$(curl $KMS_URL/app/setKeyReleasePolicyClaims -k \
        -H "Content-Type: application/cose" \
        --data-binary "$signed_payload" \
        -s \
        --cacert $KMS_SERVICE_CERT_PATH -w '\n')

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