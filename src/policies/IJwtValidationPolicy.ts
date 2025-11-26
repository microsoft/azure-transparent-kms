// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.


export interface IJwtValidationPolicy {
    issuer: string;
    validation_policy: IJwtValidationPolicyData;
}

/**
 * Interface representing the validation policy for a JWT issuer.
 */
export interface IJwtValidationPolicyData {
    iss: string;
    aud: string;
    appid: string;
    appidacr: string;
    idp: string;
    idtyp: string;
    oid: string;
    sub: string;
    tid: string;
    ver: string;
    xms_mirid: string;
  }