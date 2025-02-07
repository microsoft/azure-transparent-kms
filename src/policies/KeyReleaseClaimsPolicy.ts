// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { KeyReleaseClaimsPolicyStore } from "../repositories/KeyReleaseClaimsPolicyStore";
import { AzureVMKeyReleasePolicyClaims } from "./AzureVMKeyReleasePolicyClaims";

export const add = (
  map: KeyReleaseClaimsPolicyStore,
  claimType: string,
  claims: AzureVMKeyReleasePolicyClaims
): void => {
  console.log(`Add claims from key release policy: ${JSON.stringify(claims)}`);
  map.storeClaims(claimType, claims);
};


export const remove = (
  map: KeyReleaseClaimsPolicyStore,
  claimType: string,
  claims: AzureVMKeyReleasePolicyClaims
): void => {
  console.log(`Remove claims from key release policy : ${JSON.stringify(claims)}`);
  map.removeClaims(claimType, claims);
};
