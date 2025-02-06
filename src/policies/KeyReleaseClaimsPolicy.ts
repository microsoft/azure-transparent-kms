// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { KeyReleaseClaimsPolicyStore } from "../repositories/KeyReleaseClaimsPolicyStore";
import { IKeyReleasePolicyClaims } from "./IKeyReleasePolicyClaims";

export const add = (
  map: KeyReleaseClaimsPolicyStore,
  claims: IKeyReleasePolicyClaims
): void => {
  console.log(`Add claims from key release policy: ${JSON.stringify(claims)}`);
  map.storeClaims(claims);
};


export const remove = (
  map: KeyReleaseClaimsPolicyStore,
  claims: IKeyReleasePolicyClaims
): void => {
  console.log(`Remove claims from key release policy : ${JSON.stringify(claims)}`);
  map.removeClaims(claims);
};
