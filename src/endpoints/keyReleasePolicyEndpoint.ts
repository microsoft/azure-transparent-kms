// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ServiceResult } from "../utils/ServiceResult";
import { enableEndpoint } from "../utils/Tooling";
import { keyReleasePolicyMapName, keyReleasePolicyMap } from "../repositories/Maps";
import { ServiceRequest } from "../utils/ServiceRequest";
import { KeyReleasePolicy } from "../policies/KeyReleasePolicy";
import { IKeyReleasePolicy } from "../policies/IKeyReleasePolicy";
import { LogContext } from "../utils/Logger";
import { ccf } from "@microsoft/ccf-app/global";
import {
  add,
  addOperator,
  remove,
  removeOperator,
  IKeyReleasePolicyClaimsExtended,
} from "../policies/KeyReleaseClaimsPolicy";

// Enable the endpoint
enableEndpoint();

/**
 * Adds or removes claims and operator claims in the key release policy.
 * Supports claims + operators: gte, gt, in.
 */
export const setKeyReleasePolicyClaims = (
  request: ccfapp.Request<{
    claimType: "add" | "remove";
    keyReleaseClaims: Partial<IKeyReleasePolicyClaimsExtended>;
  }>
): ServiceResult<string> => {
  const logContext = new LogContext().appendScope("setKeyReleasePolicyClaimsEndpoint");
  const serviceRequest = new ServiceRequest<
    { claimType: string; keyReleaseClaims: Partial<IKeyReleasePolicyClaimsExtended> }
  >(logContext, request);

  // Check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  const { body } = serviceRequest;

  if (!body || !body.claimType || !body.keyReleaseClaims) {
    return ServiceResult.Failed<string>(
      { errorMessage: "Invalid request body: 'claimType' and 'keyReleaseClaims' are required." },
      400,
      logContext
    );
  }
  console.log(`Request body: ${JSON.stringify(body)}`, logContext);

  const { claimType, keyReleaseClaims } = body;

  // Ensure at least one valid section is present
  if (
    !keyReleaseClaims.claims &&
    !keyReleaseClaims.gte &&
    !keyReleaseClaims.gt &&
    !keyReleaseClaims.in
  ) {
    return ServiceResult.Failed<string>(
      {
        errorMessage:
          "At least one of 'claims', 'gte', 'gt', or 'in' must be present in keyReleaseClaims.",
      },
      400,
      logContext
    );
  }

  try {
    if (claimType === "add") {
      if (keyReleaseClaims.claims) add(keyReleasePolicyMap, "claims", keyReleaseClaims.claims);
      if (keyReleaseClaims.gte) addOperator(keyReleasePolicyMap, "gte", keyReleaseClaims.gte);
      if (keyReleaseClaims.gt) addOperator(keyReleasePolicyMap, "gt", keyReleaseClaims.gt);
      if (keyReleaseClaims.in) addOperator(keyReleasePolicyMap, "in", keyReleaseClaims.in);
    } else if (claimType === "remove") {
      if (keyReleaseClaims.claims) remove(keyReleasePolicyMap, "claims", keyReleaseClaims.claims);
      if (keyReleaseClaims.gte) removeOperator(keyReleasePolicyMap, "gte", keyReleaseClaims.gte);
      if (keyReleaseClaims.gt) removeOperator(keyReleasePolicyMap, "gt", keyReleaseClaims.gt);
      if (keyReleaseClaims.in) removeOperator(keyReleasePolicyMap, "in", keyReleaseClaims.in);
    } else {
      return ServiceResult.Failed<string>(
        { errorMessage: `Unsupported claimType: ${claimType}` },
        400,
        logContext
      );
    }

    return ServiceResult.Succeeded<string>(`Operation ${claimType} successful.`, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};

/**
 * Retrieves the key release policy.
 */
export const keyReleasePolicy = (
  request: ccfapp.Request<void>
): ServiceResult<string | IKeyReleasePolicy> => {
  const logContext = new LogContext().appendScope("keyReleasePolicyEndpoint");
  const serviceRequest = new ServiceRequest<void>(logContext, request);

  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  try {
    const result = KeyReleasePolicy.getKeyReleasePolicyFromMap(
      ccf.kv[keyReleasePolicyMapName],
      logContext
    );
    console.log(`Key release policy Result: ${JSON.stringify(result)}`, logContext);
    return ServiceResult.Succeeded<IKeyReleasePolicy>(result, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};