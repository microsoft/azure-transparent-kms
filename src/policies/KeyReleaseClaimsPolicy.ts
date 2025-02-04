// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { IClaims } from "../policies/IKeyReleaseClaims";
import { keyReleasePolicyMap } from "../repositories/Maps";

export class KeyReleaseClaims {

    static add(
        map: typeof keyReleasePolicyMap,
        type: string,
        claims: IClaims,
    ): void {
        console.log(`Add claims from key release policy for ${type}: ${JSON.stringify(claims)}`);
        keyReleasePolicyMap.storeClaims(type, claims);
    }

    static remove(
        map: typeof keyReleasePolicyMap,
        type: string,
        claims: IClaims,
    ): void {
        console.log(`Remove claims from key release policy for ${type}: ${JSON.stringify(claims)}`);
        keyReleasePolicyMap.removeClaims(type, claims);
    }
}