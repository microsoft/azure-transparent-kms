// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// @yf23: This file should be merged with KeyReleasePolicy.ts to have a single file for adding/removing claims and policies
import { KeyReleaseClaimsPolicyStore } from "../repositories/KeyReleaseClaimsPolicyStore";
import { IMaaKeyReleasePolicyClaims } from "./IMaaKeyReleasePolicyClaims";
import { IKeyReleasePolicySnpProps } from "./IKeyReleasePolicySnpProps";

// Note: This interface should be clarified by the team if it should support IKeyReleasePolicySnpProps or not 
// for now to avoid breaking changes we will keep it as is and make it compatible to set SNP claims
export type IKeyReleasePolicyClaims = Partial<IKeyReleasePolicySnpProps> & Partial<IMaaKeyReleasePolicyClaims>;

// Wrapper class to provide Add and Remove functionality for claims on KeyReleaseClaimsPolicyStore
// Check with the team if this should be part of Policy or just a helper class

// Add claims to the store
export const add = (
  map: KeyReleaseClaimsPolicyStore,
  claimType: string,
  claims: IKeyReleasePolicyClaims
): void => {
  console.log(`Add claims from key release policy: ${JSON.stringify(claims)}`);
  map.storeClaims(claimType, claims);
};

// Remove claims from the store
export const remove = (
  map: KeyReleaseClaimsPolicyStore,
  claimType: string,
  claims: IKeyReleasePolicyClaims
): void => {
  console.log(`Remove claims from key release policy : ${JSON.stringify(claims)}`);
  map.removeIndividualClaims(claimType, claims);
};
