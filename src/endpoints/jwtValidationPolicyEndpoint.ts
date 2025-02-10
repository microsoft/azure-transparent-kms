// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { enableEndpoint } from "../utils/Tooling";
import { ServiceResult } from "../utils/ServiceResult";
import { ServiceRequest } from "../utils/ServiceRequest";
import { LogContext } from "../utils/Logger";
import { IJwtValidationPolicy } from "../policies/IJwtValidationPolicy";
import { jwtValidationPolicyMap, settingsPolicyMap } from "../repositories/Maps";
import { addJwtValidationPolicyFromStore, removeJwtValidationPolicyFromStore } from "../policies/JwtValidationPolicy";
import { Settings } from "../policies/Settings";

// Enable the endpoint
enableEndpoint();

/**
 * Endpoint to set JWT Validation Policy.
 * @param request A CCF request containing the JWT validation policy.
 * @returns A ServiceResult indicating success or failure.
 */
export const setJwtValidationPolicy = (
    request: ccfapp.Request<{ jwt_validation_policy: IJwtValidationPolicy }>,
): ServiceResult<string> => {
    const logContext = new LogContext().appendScope("setJwtValidationPolicyEndpoint");
    const serviceRequest = new ServiceRequest<{ jwt_validation_policy: IJwtValidationPolicy }>(logContext, request);
    let appSettings: Settings = Settings.loadSettingsFromMap(settingsPolicyMap, logContext);

    console.log(appSettings.settings.service);
    if (appSettings.settings.service.ledgerType !== "acl") {
        return ServiceResult.Failed<string>(
            { errorMessage: `Invalid Operation: for LedgerType:${appSettings.settings.service.ledgerType}` },
            400,
            logContext
        );
    }
    // Check if caller has a valid identity
    const [_, isValidIdentity] = serviceRequest.isAuthenticated();
    if (isValidIdentity.failure) return isValidIdentity;

    const { body } = serviceRequest;
    if (!body || !body.jwt_validation_policy) {
        return ServiceResult.Failed<string>(
            { errorMessage: "Invalid request body: 'jwt_validation_policy' is required." },
            400,
            logContext
        );
    }

    const jwtValidationPolicy: IJwtValidationPolicy = body.jwt_validation_policy;

    try {
        // Validate and apply the policy
        addJwtValidationPolicyFromStore(jwtValidationPolicyMap, jwtValidationPolicy);

        return ServiceResult.Succeeded<string>("JWT Validation policy set successfully.", logContext);
    } catch (error: any) {
        return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
    }
};

/**
 * Endpoint to set key rotation policy.
 * @param request A CCF request containing the key rotation policy.
 * @returns A ServiceResult indicating success or failure.
 */
export const removeJwtValidationPolicy = (
    request: ccfapp.Request<{ issuer: string }>,
): ServiceResult<string> => {
    const logContext = new LogContext().appendScope("removeJwtValidationPolicy");
    const serviceRequest = new ServiceRequest<{ issuer: string }>(logContext, request);
    let appSettings: Settings = Settings.loadSettingsFromMap(settingsPolicyMap, logContext);

    console.log(appSettings.settings.service);
    if (appSettings.settings.service.ledgerType !== "acl") {
        return ServiceResult.Failed<string>(
            { errorMessage: `Invalid Operation: for LedgerType:${appSettings.settings.service.ledgerType}` },
            400,
            logContext
        );
    }

    // Check if caller has a valid identity
    const [_, isValidIdentity] = serviceRequest.isAuthenticated();
    if (isValidIdentity.failure) return isValidIdentity;

    const { body } = serviceRequest;
    if (!body || !body.issuer) {
        return ServiceResult.Failed<string>(
            { errorMessage: "Invalid request body: 'issuer' is required." },
            400,
            logContext
        );
    }

    const issuer: string = body.issuer;

    try {
        // Remove Policy on Issuer
        removeJwtValidationPolicyFromStore(jwtValidationPolicyMap, issuer);

        return ServiceResult.Succeeded<string>(`Removed JWT Validation Policy for issuer: ${issuer}.`, logContext);
    } catch (error: any) {
        return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
    }
};