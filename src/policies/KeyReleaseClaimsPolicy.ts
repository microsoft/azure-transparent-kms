// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { IMaaAttestationReport } from "../attestation/IMaaAttestationReport";
import { IAttestationReport } from "../attestation/ISnpAttestationReport";
import { KeyReleaseClaimsPolicyStore } from "../repositories/KeyReleaseClaimsPolicyStore";

export type KeyReleasePolicyClaims = Partial<IAttestationReport> & Partial<IMaaAttestationReport>;

export const add = (
  map: KeyReleaseClaimsPolicyStore,
  claimType: string,
  claims: KeyReleasePolicyClaims
): void => {
  console.log(`Add claims from key release policy: ${JSON.stringify(claims)}`);
  map.storeClaims(claimType, claims);
};


export const remove = (
  map: KeyReleaseClaimsPolicyStore,
  claimType: string,
  claims: KeyReleasePolicyClaims
): void => {
  console.log(`Remove claims from key release policy : ${JSON.stringify(claims)}`);
  map.removeClaims(claimType, claims);
};
