// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { ccf } from "@microsoft/ccf-app/global";
import { LastestItemStore } from "./LastestItemStore";
import { KeyStore } from "./KeyStore";
import {KeyRotationPolicyStore} from "./KeyRotationPolicyStore"
import { KeyReleaseClaimsPolicyStore } from "./KeyReleaseClaimsPolicyStore";

//#region KMS Stores
// Stores
export const hpkeKeysMap = new KeyStore("HpkeKeys");
export const hpkeKeyIdMap = new LastestItemStore<number, string>("HpkeKeyids");
export const keyReleaseMapName = "public:kms.policies.key_release";
export const keyReleasePolicyMap = new KeyReleaseClaimsPolicyStore(keyReleaseMapName);
export const settingsMapName = "public:ccf.gov.policies.settings";
export const settingsPolicyMap = ccf.kv[settingsMapName];
export const keyRotationSetName = "public:kms.policies.key_rotation";
export const keyRotationPolicySet = new KeyRotationPolicyStore(keyRotationSetName);
//#endregion
