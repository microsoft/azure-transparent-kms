import * as ccfapp from "@microsoft/ccf-app";
import { enableEndpoint } from "../utils/Tooling";
import { ServiceResult } from "../utils/ServiceResult";
import { ServiceRequest } from "../utils/ServiceRequest";
import { KeyReleaseClaims } from "../policies/KeyReleaseClaims";
import { keyReleasePolicyMap } from "../repositories/Maps";
import { LogContext } from "../utils/Logger";


// Enable the endpoint
enableEndpoint();

/**
 * Adds or removes claims in the key release policy.
 * @param request A CCF request containing the operation type and claims.
 * @returns A ServiceResult with the operation status.
 */
export const setKeyReleaseClaims = (
  request: ccfapp.Request<{ type: string; claims: Record<string, any> }>,
): ServiceResult<string> => {

  const logContext = new LogContext().appendScope("keyReleasePolicyClaimsEndpoint");
  const serviceRequest = new ServiceRequest<{ type: string; claims: Record<string, any> }>(logContext, request);

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

  try {
    if (type === "add") {
        KeyReleaseClaims.add(keyReleasePolicyMap, "claims", claims);
    } else if (type === "remove") {
        KeyReleaseClaims.remove(keyReleasePolicyMap, "claims", claims);
    } else {
      return ServiceResult.Failed<string>({ errorMessage: `Unsupported operation: ${type}` }, 400, logContext);
    }
    return ServiceResult.Succeeded<string>(`Operation ${type} successful.`, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};
