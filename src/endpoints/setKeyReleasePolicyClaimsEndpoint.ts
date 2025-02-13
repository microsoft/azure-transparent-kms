// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { enableEndpoint } from "../utils/Tooling";
import { ServiceResult } from "../utils/ServiceResult";
import { ServiceRequest } from "../utils/ServiceRequest";
import { keyReleasePolicyMap } from "../repositories/Maps";
import { LogContext } from "../utils/Logger";
import { add, KeyReleasePolicyClaims, remove } from "../policies/KeyReleaseClaimsPolicy";

// Enable the endpoint
enableEndpoint();

/**
 * Adds or removes claims in the key release policy.
 * @param request A CCF request containing the operation type and claims.
 * @returns A ServiceResult with the operation status.
 */

export const setKeyReleasePolicyClaims = (
  request: ccfapp.Request<{ claimType: "add" | "remove"; claims: Partial<KeyReleasePolicyClaims> }>, // Updated claims type
): ServiceResult<string> => {

  const logContext = new LogContext().appendScope("setKeyReleasePolicyClaimsEndpoint");
  const serviceRequest = new ServiceRequest<{ claimType: string; claims: Partial<KeyReleasePolicyClaims> }>(logContext, request);

  // Check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;
  console.log(serviceRequest);

  const { body } = serviceRequest;
  if (!body || !body.claimType || !body.claims) {
    return ServiceResult.Failed<string>(
      { errorMessage: "Invalid request body: 'type' and 'claims' are required." },
      400,
      logContext
    );
  }

  const { claimType, claims } = body;

  try {
    add(keyReleasePolicyMap, claimType, claims);
    return ServiceResult.Succeeded<string>(`Operation ${claimType} successful.`, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};


/**
 * Adds or removes claims in the key release policy.
 * @param request A CCF request containing the operation type and claims.
 * @returns A ServiceResult with the operation status.
 */
export const removeKeyReleasePolicyClaims = (
  request: ccfapp.Request<{ claimType: string; claims: Partial<KeyReleasePolicyClaims> }>, // Updated claims type
): ServiceResult<string> => {

  const logContext = new LogContext().appendScope("removeKeyReleasePolicyClaimsEndpoint");
  const serviceRequest = new ServiceRequest<{ claimType: string; claims: Partial<KeyReleasePolicyClaims> }>(logContext, request);

  // Check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  const { body } = serviceRequest;
  if (!body || !body.claimType || !body.claims) {
    return ServiceResult.Failed<string>(
      { errorMessage: "Invalid request body: 'type' and 'claims' are required." },
      400,
      logContext
    );
  }

  const { claimType, claims } = body;

  // Validate claims: Ensure all keys exist in IKeyReleaseClaims
  const validKeys = new Set(Object.keys({} as KeyReleasePolicyClaims));
  const invalidKeys = Object.keys(claims).filter(key => !validKeys.has(key));

  if (invalidKeys.length > 0) {
    return ServiceResult.Failed<string>(
      { errorMessage: `Invalid claim keys detected: ${invalidKeys.join(", ")}` },
      400,
      logContext
    );
  }

  try {
    remove(keyReleasePolicyMap, claimType, claims);
    return ServiceResult.Succeeded<string>(`Operation ${claimType} successful.`, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};