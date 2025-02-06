// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { enableEndpoint } from "../utils/Tooling";
import { ServiceResult } from "../utils/ServiceResult";
import { ServiceRequest } from "../utils/ServiceRequest";
import { keyReleasePolicyMap } from "../repositories/Maps";
import { LogContext } from "../utils/Logger";
import { IKeyReleasePolicyClaims } from "../policies/IKeyReleasePolicyClaims";
import { add as addKeyReleasPolicyClaims, remove as removeKeyReleasePolicyClaims } from "../policies/KeyReleaseClaimsPolicy";

// Enable the endpoint
enableEndpoint();

/**
 * Adds or removes claims in the key release policy.
 * @param request A CCF request containing the operation type and claims.
 * @returns A ServiceResult with the operation status.
 */
export const setKeyReleasePolicyClaims = (
  request: ccfapp.Request<{ type: string; claims: Partial<IKeyReleasePolicyClaims> }>, // Updated claims type
): ServiceResult<string> => {

  const logContext = new LogContext().appendScope("setKeyReleasePolicyClaimsEndpoint");
  const serviceRequest = new ServiceRequest<{ type: string; claims: Partial<IKeyReleasePolicyClaims> }>(logContext, request);

  // Check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  const { body } = serviceRequest;
  if (!body || !body.type || !body.claims) {
    return ServiceResult.Failed<string>(
      { errorMessage: "Invalid request body: 'type' and 'claims' are required." },
      400,
      logContext
    );
  }

  const { type, claims } = body;

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
    if (type === "add") {
      addKeyReleasPolicyClaims(keyReleasePolicyMap, claims);
    } else if (type === "remove") {
      removeKeyReleasePolicyClaims(keyReleasePolicyMap, claims);
    } else {
      return ServiceResult.Failed<string>({ errorMessage: `Unsupported operation: ${type}` }, 400, logContext);
    }

    return ServiceResult.Succeeded<string>(`Operation ${type} successful.`, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};