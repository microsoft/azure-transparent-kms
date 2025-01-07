import * as ccfapp from "@microsoft/ccf-app";
import { enableEndpoint } from "../utils/Tooling";
import { ServiceResult } from "../utils/ServiceResult";
import { ServiceRequest } from "../utils/ServiceRequest";
import { KeyRotationPolicy } from "../policies/KeyRotationPolicy";
import { keyRotationPolicyMap } from "../repositories/Maps";
import { LogContext } from "../utils/Logger";


// Enable the endpoint
enableEndpoint();

/**
 * Endpoint to set key rotation policy.
 * @param request A CCF request containing the key rotation policy.
 * @returns A ServiceResult indicating success or failure.
 */
export const setKeyRotationPolicy = (
    request: ccfapp.Request<{ key_rotation_policy: Record<string, any> }>,
  ): ServiceResult<string> => {
    const logContext = new LogContext().appendScope("keyRotationPolicyEndpoint");
    const serviceRequest = new ServiceRequest<{ key_rotation_policy: Record<string, any> }>(logContext, request);
  
    // Check if caller has a valid identity
    const [_, isValidIdentity] = serviceRequest.isAuthenticated();
    if (isValidIdentity.failure) return isValidIdentity;
  
    const { body } = serviceRequest;
    if (!body ||  !body.key_rotation_policy) {
      return ServiceResult.Failed<string>(
        { errorMessage: "Invalid request body: 'key_rotation_policy' is required." },
        400,
        logContext
      );
    }
    const { key_rotation_policy } = body;

  
    try {
      // Validate and apply the policy
      KeyRotationPolicy.validate(key_rotation_policy);
      KeyRotationPolicy.apply(keyRotationPolicyMap, key_rotation_policy);
  
      return ServiceResult.Succeeded<string>("Key rotation policy set successfully.", logContext);
    } catch (error: any) {
      return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
    }
  };
  