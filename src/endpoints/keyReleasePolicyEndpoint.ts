// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ServiceResult } from "../utils/ServiceResult";
import { enableEndpoint } from "../utils/Tooling";
import { keyReleaseMapName, keyReleasePolicyMap } from "../repositories/Maps";
import { ServiceRequest } from "../utils/ServiceRequest";
import { KeyReleasePolicy } from "../policies/KeyReleasePolicy";
import { IKeyReleasePolicy } from "../policies/IKeyReleasePolicy";
import { LogContext } from "../utils/Logger";
import { ccf } from "@microsoft/ccf-app/global";
import { add, IKeyReleasePolicyClaims, remove } from "../policies/KeyReleaseClaimsPolicy";

// Enable the endpoint
enableEndpoint();

/**
 * Adds or removes claims in the key release policy.
 * @param request A CCF request containing the operation type and claims.
 * @returns A ServiceResult with the operation status.
 */
// @yf23 to update this to use IKeyReleasePolicy interface
export const setKeyReleasePolicyClaims = (
  request: ccfapp.Request<{ claimType: "add" | "remove"; claims: Partial<IKeyReleasePolicyClaims> }>, // Updated claims type
): ServiceResult<string> => {

  const logContext = new LogContext().appendScope("setKeyReleasePolicyClaimsEndpoint");
  const serviceRequest = new ServiceRequest<{ claimType: string; claims: Partial<IKeyReleasePolicyClaims> }>(logContext, request);

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
// @yf23 to update this to use IKeyReleasePolicy interface
export const removeKeyReleasePolicyClaims = (
  request: ccfapp.Request<{ claimType: string; claims: Partial<IKeyReleasePolicyClaims> }>, // Updated claims type
): ServiceResult<string> => {

  const logContext = new LogContext().appendScope("removeKeyReleasePolicyClaimsEndpoint");
  const serviceRequest = new ServiceRequest<{ claimType: string; claims: Partial<IKeyReleasePolicyClaims> }>(logContext, request);

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
  const validKeys = new Set(Object.keys({} as IKeyReleasePolicyClaims));
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

/**
 * Retrieves the key release policy.
 * @returns A ServiceResult containing the key release policy properties.
 */
export const keyReleasePolicy = (
  request: ccfapp.Request<void>,
): ServiceResult<string | IKeyReleasePolicy> => {
  const logContext = new LogContext().appendScope("keyReleasePolicyEndpoint");
  const serviceRequest = new ServiceRequest<void>(logContext, request);

  // check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  try {
    const result =
      KeyReleasePolicy.getKeyReleasePolicyFromMap(ccf.kv[keyReleaseMapName], logContext);
      return ServiceResult.Succeeded<IKeyReleasePolicy>(result, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};
