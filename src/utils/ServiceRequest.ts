// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
import * as ccfapp from "@microsoft/ccf-app";
import { ErrorResponse, ServiceResult } from "./ServiceResult";
import { queryParams } from "./Tooling";
import { AuthenticationService } from "../authorization/AuthenticationService";
import { Logger, LogContext } from "./Logger";
import { Settings } from "../policies/Settings";
import { settingsPolicyMap } from "../repositories/Maps";
import { ccf } from "@microsoft/ccf-app/global";

/**
 * A generic request.
 * Return a dictionary with the request properties.
 * Throw an error if the request is invalid.
 */
export class ServiceRequest<T> {
  public readonly success: boolean;
  public readonly body?: T;
  public readonly headers?: { [key: string]: string };
  public readonly query?: { [key: string]: string };
  public readonly error?: ErrorResponse;
  public readonly requestId?: string;
  private readonly logContext: LogContext;

  constructor(
    public logcontext: LogContext | string,
    public request: ccfapp.Request<T>,
  ) {
    // Set log context if passed in scope string
    if (typeof logcontext === "string") {
      this.logContext = new LogContext().appendScope(logcontext);
    } else {
      this.logContext = logcontext;
    }

    // Set the log level from the settings
    let settings: Settings;
    try {
      settings = Settings.loadSettingsFromMap(settingsPolicyMap, this.logContext);
    } catch (error) {
      const errorMessage = `${this.logContext.getBaseScope()}: Error loading settings: ${error}`;
      Logger.error(errorMessage, this.logContext);
      this.error = {
        errorMessage,
      };
      this.success = false;
      return;
    }

    Logger.setLogLevelFromSettings(settings);
    Settings.logSettings(settings.settings);

    // Set request ID
    this.headers = request.headers;
    const requestIdHeaderList = [
      'x-ms-kms-request-id',
      'x-ms-request-id',
      'x-request-id',
      'request-id',
      'requestid',
    ]
    const requestIdFromHeader = (logcontext as LogContext).requestId || requestIdHeaderList
      .map((header) => this.headers ? this.headers[header] : undefined)
      .find((header) => header !== undefined);
    if (!requestIdFromHeader) {
      this.requestId = Date.now().toString();
      Logger.warn(`Request ID not provided. Using current timestamp as request ID: ${this.requestId}`, this.logContext);
    } else {
      this.requestId = requestIdFromHeader;
    }
    this.logContext.setRequestId(this.requestId);

    Logger.info(`ServiceRequest`, this.logContext);

    // Log request
    // Create a shallow copy of the request object without the Authorization header
    const { Authorization, authorization, ...otherHeaders } = request.headers;
    let requestWithoutAuth;
    if (Authorization || authorization) {
      requestWithoutAuth = {
        ...request,
        headers: {
          ...otherHeaders,
          authorization: "token deleted for logging",
        }
      }
    }
    else {
      requestWithoutAuth = {
        ...request,
        headers: {
          ...otherHeaders,
        },
      }
    }

    Logger.info(`Request:`, this.logContext, JSON.stringify(requestWithoutAuth, null, 2));
    this.query = queryParams(request, this.logContext);

    try {
      // Check if this is a COSE-signed request
      const isCoseRequest = request.caller &&
                           (request.caller as any).policy === 'user_cose_sign1' &&
                           (request.caller as ccfapp.UserCOSESign1AuthnIdentity).cose &&
                           (request.caller as ccfapp.UserCOSESign1AuthnIdentity).cose.content;

      if (isCoseRequest) {
        // Handle COSE-signed request by parsing the content
        try {
          const caller = request.caller as ccfapp.UserCOSESign1AuthnIdentity;
          let requestBody = ccf.bufToJsonCompatible(caller.cose.content);

          // Parse the JSON content
          this.body = requestBody as T;
          Logger.info(`Parsed COSE body:`, this.logContext, JSON.stringify(this.body));
        } catch (coseError) {
          Logger.error(`Failed to parse COSE content: ${coseError}`, this.logContext);
          this.error = {
            errorMessage: `${this.logContext.getBaseScope()}: Failed to parse COSE content: ${coseError}`,
          };
          this.success = false;
          return;
        }
      } else {
        // For regular JSON requests, use the body directly
        this.body = request.body.json();
      }

    } catch (exception) {
      this.error = {
        errorMessage: `${this.logContext.getBaseScope()}: No valid JSON request for ${this.logContext.getFormattedScopeString()}`,
      };
      this.success = false;
      return;
    }
    this.success = true;
  }

  /**
   * Checks if the API is authenticated.
   * @returns {boolean} Returns true if the API is authenticated, otherwise false.
   */
  public isAuthenticated(): [
    ccfapp.AuthnIdentityCommon | undefined,
    ServiceResult<string>,
  ] {
    const [policy, isValidIdentity] =
      new AuthenticationService(this.logContext).isAuthenticated(this.request);

    Logger.debug(
      `Authorization: isAuthenticated-> ${JSON.stringify(isValidIdentity)}`, this.logContext
    );
    return [policy, isValidIdentity];
  }
}