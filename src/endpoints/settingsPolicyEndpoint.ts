// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import { IService, ISettings, Settings } from "../policies/Settings";
import { settingsMapName, settingsPolicyMap } from "../repositories/Maps";
import { LogContext } from "../utils/Logger";
import { ServiceRequest } from "../utils/ServiceRequest";
import { ServiceResult } from "../utils/ServiceResult";
import { enableEndpoint } from "../utils/Tooling";


// Enable the endpoint
enableEndpoint();

const key = "settings_policy";
const keyBuf = ccf.strToBuf(key);

/**
 * Endpoint to set the Settings Policy.
 * @param request A CCF request containing the settings olicy.
 * @returns A ServiceResult indicating success or failure.
 */
export const setSettingsPolicy = (
    request: ccfapp.Request<{ set_settings_policy: IService }>,
): ServiceResult<string> => {
    const logContext = new LogContext().appendScope("setSettingsPolicyEndpoint");
    const serviceRequest = new ServiceRequest<{ set_settings_policy: IService }>(logContext, request);

    // Check if caller has a valid identity
    const [_, isValidIdentity] = serviceRequest.isAuthenticated();
    if (isValidIdentity.failure) return isValidIdentity;

    const { body } = serviceRequest;
    if (!body || !body.set_settings_policy) {
        return ServiceResult.Failed<string>(
            { errorMessage: "Invalid request body: 'set_settings_policy' is required." },
            400,
            logContext
        );
    }

    const settings_policy: IService = body.set_settings_policy;

    try {
        // Validate and apply the policy
        const jsonItems = JSON.stringify(settings_policy);
        const jsonItemsBuf = ccf.strToBuf(jsonItems);
        ccf.kv[settingsMapName].set(keyBuf, jsonItemsBuf);
        console.log(
          `[INFO] [scope=set_settings_policy] Settings policy ${jsonItems} saved in ${settingsMapName}`,
        );

        return ServiceResult.Succeeded<string>("Key rotation policy set successfully.", logContext);
    } catch (error: any) {
        return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
    }
};

/**
 * Retrieves the settings policy.
 * @returns A ServiceResult containing the settings policy properties.
 */
export const settingsPolicy = (
  request: ccfapp.Request<void>
): ServiceResult<string | ISettings> => {
  const logContext = new LogContext().appendScope("settingsPolicyEndpoint");
  const serviceRequest = new ServiceRequest<void>(logContext, request);

  // check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  try {
    const result =
      Settings.loadSettingsFromMap(settingsPolicyMap, logContext).settings;
    return ServiceResult.Succeeded<ISettings>(result, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};
