// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { JwtValidationPolicyStore } from "../repositories/JwtValidationPolicyStore";
import { IJwtValidationPolicy } from "./IJwtValidationPolicy";

export function addJwtValidationPolicyFromStore(
    jwtValidationPolicyStore: JwtValidationPolicyStore,
    policy: IJwtValidationPolicy
): void {
    console.log(`Add JWT Validation Policy for issuer ${policy.issuer}: ${JSON.stringify(policy.validation_policy)}`);
    jwtValidationPolicyStore.storeJwtValidationPolicy(policy);
}

export function removeJwtValidationPolicyFromStore(
    jwtValidationPolicyStore: JwtValidationPolicyStore,
    issuer: string
): void {
    console.log(`Remove JWT Validation Policy for issuer ${issuer}`);
    jwtValidationPolicyStore.deleteJwtValidationPolicy(issuer);
}