// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { ccf } from "@microsoft/ccf-app/global";
import { LastestItemStore } from "./LastestItemStore";
import { KeyStore } from "./KeyStore";
import {KeyRotationPolicyStore} from "./KeyRotationPolicyStore"
import { KeyReleaseClaimsPolicyStore } from "./KeyReleaseClaimsPolicyStore";
import { JwtValidationPolicyStore } from "./JwtValidationPolicyStore";

//#region KMS Stores
// Stores
export const hpkeKeysMap = new KeyStore("HpkeKeys");
export const hpkeKeyIdMap = new LastestItemStore<number, string>("HpkeKeyids");
export const keyReleaseMapName = "public:ccf.gov.policies.key_release";
export const keyReleasePolicyMap = ccf.kv[keyReleaseMapName];
export const keyReleasePolicyApplicationTableName = "public:kms.policies.key_release";
export const keyReleasePolicyApplicationTableMap = new KeyReleaseClaimsPolicyStore(keyReleasePolicyApplicationTableName);
export const settingsMapName = "public:ccf.gov.policies.settings";
export const settingsPolicyMap = ccf.kv[settingsMapName];
export const settingsApplicationTableMapName = "public:kms.policies.settings";
export const settingsPolicyApplicationTableMap = ccf.kv[settingsApplicationTableMapName];
export const keyRotationSetName = "public:kms.policies.key_rotation";
export const keyRotationPolicySet = new KeyRotationPolicyStore(keyRotationSetName);
export const jwtValidationPolicyMapName = "public:kms.policies.jwt_validation";
export const jwtValidationPolicyMap = new JwtValidationPolicyStore(jwtValidationPolicyMapName);
//#endregion
