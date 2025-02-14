// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { IMaaAttestationReport } from "../attestation/IMaaAttestationReport";
import { IAttestationReport } from "../attestation/ISnpAttestationReport";
import { KeyReleaseClaimsPolicyStore } from "../repositories/KeyReleaseClaimsPolicyStore";

export type IKeyReleasePolicyClaims = Partial<IAttestationReport> & Partial<IMaaAttestationReport>;

export const add = (
  map: KeyReleaseClaimsPolicyStore,
  claimType: string,
  claims: IKeyReleasePolicyClaims
): void => {
  console.log(`Add claims from key release policy: ${JSON.stringify(claims)}`);
  map.storeClaims(claimType, claims);
};


export const remove = (
  map: KeyReleaseClaimsPolicyStore,
  claimType: string,
  claims: IKeyReleasePolicyClaims
): void => {
  console.log(`Remove claims from key release policy : ${JSON.stringify(claims)}`);
  map.removeIndividualClaims(claimType, claims);
};
