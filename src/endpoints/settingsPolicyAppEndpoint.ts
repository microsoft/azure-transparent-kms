// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import { IService, ISettings, Settings } from "../policies/Settings";
import { settingsApplicationTableMapName, settingsPolicyApplicationTableMap } from "../repositories/Maps";
import { LogContext } from "../utils/Logger";
import { ServiceRequest } from "../utils/ServiceRequest";
import { ServiceResult } from "../utils/ServiceResult";
import { enableEndpoint } from "../utils/Tooling";


// Enable the endpoint
enableEndpoint();
// Override this by reading Default Settings
// By Default Ledger_Type is MCCF
var ledgerType = "acl";

const key = "settings_policy";
const keyBuf = ccf.strToBuf(key);

/**
 * Endpoint to set the Settings Policy.
 * @param request A CCF request containing the settings olicy.
 * @returns A ServiceResult indicating success or failure.
 */
export const setSettingsPolicy = (
    request: ccfapp.Request<{ settings_policy: IService }>,
): ServiceResult<string> => {
    const logContext = new LogContext().appendScope("setSettingsPolicyAppTableEndpoint");
    const serviceRequest = new ServiceRequest<{ settings_policy: IService }>(logContext, request);

    // Check if caller has a valid identity
    const [_, isValidIdentity] = serviceRequest.isAuthenticated();
    if (isValidIdentity.failure) return isValidIdentity;

    const { body } = serviceRequest;
    if (!body || !body.settings_policy) {
        return ServiceResult.Failed<string>(
            { errorMessage: "Invalid request body: 'set_settings_policy' is required." },
            400,
            logContext
        );
    }

    const settings_policy: IService = body.settings_policy;

    try {
        if (ledgerType.toLowerCase() !== "acl") {
          throw new Error(`Unsupported Operation for LEDGER_TYPE: ${ledgerType}`);
        }

        // Validate and apply the policy
        const jsonItems = JSON.stringify(settings_policy);
        const jsonItemsBuf = ccf.strToBuf(jsonItems);
        ccf.kv[settingsApplicationTableMapName].set(keyBuf, jsonItemsBuf);
        console.log(
          `[INFO] [scope=set_settings_policy] Settings policy ${jsonItems} saved in ${settingsApplicationTableMapName}`,
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
export const getSettingsPolicy = (
  request: ccfapp.Request<void>
): ServiceResult<string | ISettings> => {
  const logContext = new LogContext().appendScope("getSettingsPolicyAppTableEndpoint");
  const serviceRequest = new ServiceRequest<void>(logContext, request);

  // check if caller has a valid identity
  const [_, isValidIdentity] = serviceRequest.isAuthenticated();
  if (isValidIdentity.failure) return isValidIdentity;

  try {
    
    if (ledgerType.toLowerCase() !== "acl") {
      throw new Error(`Unsupported Operation for LEDGER_TYPE: ${ledgerType}`);
    }


    const result =
      Settings.loadSettingsFromMap(settingsPolicyApplicationTableMap, logContext).settings;
    return ServiceResult.Succeeded<ISettings>(result, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};
