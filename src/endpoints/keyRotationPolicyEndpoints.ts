// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { enableEndpoint } from "../utils/Tooling";
import { ServiceResult } from "../utils/ServiceResult";
import { ServiceRequest } from "../utils/ServiceRequest";
import { keyRotationPolicySet } from "../repositories/Maps";
import { LogContext } from "../utils/Logger";
import { IKeyRotationPolicy } from "../policies/IKeyRotationPolicy";
import { applyKeyRotationPolicy, getKeyRotationPolicyFromMap, validateKeyRotationPolicy } from "../policies/KeyRotationPolicy";

// Enable the endpoint
enableEndpoint();
// Override this by reading Default Settings
// By Default Ledger_Type is MCCF
var ledgerType = "acl";

/**
 * Endpoint to set key rotation policy.
 * @param request A CCF request containing the key rotation policy.
 * @returns A ServiceResult indicating success or failure.
 */
export const setKeyRotationPolicy = (
    request: ccfapp.Request<{ key_rotation_policy: IKeyRotationPolicy }>, // Updated to IKeyRotationPolicy
): ServiceResult<string> => {
    const logContext = new LogContext().appendScope("setKeyRotationPolicyEndpoint");
    const serviceRequest = new ServiceRequest<{ key_rotation_policy: IKeyRotationPolicy }>(logContext, request);

    if (ledgerType.toLowerCase() !== "acl") {
        throw new Error(`Unsupported Operation for LEDGER_TYPE: ${ledgerType}`);
    }

    // Check if caller has a valid identity
    const [_, isValidIdentity] = serviceRequest.isAuthenticated();
    if (isValidIdentity.failure) return isValidIdentity;

    const { body } = serviceRequest;
    if (!body || !body.key_rotation_policy) {
        return ServiceResult.Failed<string>(
            { errorMessage: "Invalid request body: 'key_rotation_policy' is required." },
            400,
            logContext
        );
    }

    const keyRotationPolicy: IKeyRotationPolicy = body.key_rotation_policy;

    try {
        // Validate and apply the policy
        validateKeyRotationPolicy(keyRotationPolicy);
        applyKeyRotationPolicy(keyRotationPolicySet, keyRotationPolicy);

        return ServiceResult.Succeeded<string>("Key rotation policy set successfully.", logContext);
    } catch (error: any) {
        return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
    }
};

/**
 * Endpoint to get the current key rotation policy.
 * @returns A ServiceResult containing the current key rotation policy or an error message.
 */
export const getKeyRotationPolicy = (
    request: ccfapp.Request<void>,
): ServiceResult<string | IKeyRotationPolicy> => {
    const logContext = new LogContext().appendScope("getKeyRotationPolicyEndpoint");
    const serviceRequest = new ServiceRequest<void>(logContext, request);

    if (ledgerType.toLowerCase() !== "acl") {
        throw new Error(`Unsupported Operation for LEDGER_TYPE: ${ledgerType}`);
    }

    // Check if caller has a valid identity
    const [_, isValidIdentity] = serviceRequest.isAuthenticated();
    if (isValidIdentity.failure) return isValidIdentity;

    try {
        const policy = getKeyRotationPolicyFromMap(keyRotationPolicySet);

        if (!policy) {
            return ServiceResult.Failed<string>({ errorMessage: "Key rotation policy not found." }, 400, logContext);
        }

        return ServiceResult.Succeeded<IKeyRotationPolicy>(policy, logContext);
    } catch (error: any) {
        return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
    }
};
