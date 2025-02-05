// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { jwtValidationPolicyMap } from "../repositories/Maps";
import { IJwtValidationPolicy } from "./IJwtValidationPolicy";

export class JwtValidationPolicy {
    static add(
        map: typeof jwtValidationPolicyMap,
        policy: IJwtValidationPolicy,
    ): void {
        console.log(`Add JWT Validation Policy for issuer ${policy.issuer}}: ${JSON.stringify(policy.validation_policy)}`);
        jwtValidationPolicyMap.storeJwtValidationPolicy(policy);
    }

    static remove(
        map: typeof jwtValidationPolicyMap,
        issuer: string,
    ): void {
        console.log(`Remove JWT Validation Policy for issuer ${issuer}}`);
        jwtValidationPolicyMap.deleteJwtValidationPolicy(issuer);
    }

}