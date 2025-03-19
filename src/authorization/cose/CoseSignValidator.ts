import * as ccfapp from "@microsoft/ccf-app";
import { IValidatorService } from "../IValidationService";
import { ServiceResult } from "../../utils/ServiceResult";
import { LogContext } from "../../utils/Logger";


export class UserCoseSignAuthnIdentity implements IValidatorService {
  private logContext: LogContext;

  constructor(logContext?: LogContext) {
    this.logContext = (logContext?.clone() || new LogContext()).appendScope("UserCoseSignAuthnIdentity");
  }

  validate(request: ccfapp.Request<any>): ServiceResult<string> {
    const userCaller = request.caller as unknown as ccfapp.UserCOSESign1AuthnIdentity;
    if (userCaller.policy !== "user_cose_sign1") {
      return ServiceResult.Failed({
        errorMessage: `Error: invalid caller identity (CoseSignValidator))}`,
        errorType: "AuthenticationError",
      }, 401, this.logContext);
    }

    const c: ccfapp.UserCOSESign1AuthnIdentity = userCaller;
    if (
      request.body.arrayBuffer().byteLength > 0 &&
      c.cose.content.byteLength == 0
    ) {
      return ServiceResult.Failed({
        errorMessage: `Error: invalid caller identity (CoseSignValidator))}`,
        errorType: "AuthenticationError",
      }, 401, this.logContext);
    }

    return ServiceResult.Succeeded("", this.logContext);
  } catch(error) {
    return ServiceResult.Failed({
      errorMessage: `Failed to parse request body: ${(error as Error).message}`,
    }, 400, this.logContext);
  }
}
