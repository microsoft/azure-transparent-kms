import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import { IValidatorService } from "./IValidationService";
import { ServiceResult } from "../utils/ServiceResult";
import { LogContext } from "../utils/Logger";

/**
 * CCF user and member authentication identity
 */
// export interface UserCoseSignAuthnIdentity extends ccfapp.AuthnIdentityCommon {
//   /**
//    * User/member ID.
//    */
//   id: string;
//   /**
//    * User/member data object.
//    */
//   data: any;
//   /**
//    * PEM-encoded user/member certificate.
//    */
//   cert: string;
//   /**
//    * A string indicating which policy accepted this request,
//    * for use when multiple policies are listed in the endpoint
//    * configuration of ``app.json``.
//    */
//   policy: string;
// }

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
  }

  /**
   * Checks if a user exists
   * @see https://microsoft.github.io/CCF/main/audit/builtin_maps.html#users-info
   * @param {string} userId userId to check if it exists
   * @returns {ServiceResult<boolean>}
   */
  public isUser(userId: string): ServiceResult<boolean> {
    const usersCerts = ccfapp.typedKv(
      "public:ccf.gov.users.certs",
      ccfapp.arrayBuffer,
      ccfapp.arrayBuffer,
    );
    const result = usersCerts.has(ccf.strToBuf(userId));
    return ServiceResult.Succeeded(result, this.logContext);
  }
}
