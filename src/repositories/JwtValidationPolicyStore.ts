// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { IJwtValidationPolicy, IJwtValidationPolicyData } from "../policies/IJwtValidationPolicy";

export class JwtValidationPolicyStore {

    private _store: ccfapp.TypedKvMap<string, IJwtValidationPolicyData>;

    constructor(public nameOfMap: string) {
        this._store = ccfapp.typedKv(nameOfMap as string, ccfapp.string, ccfapp.json<IJwtValidationPolicyData>());
    }


    /**
     * Stores a validation policy into the key-value store.
     * @param issuer The key (issuer URL).
     * @param policy The policy object (one or more fields from IJwtValidationPolicyData).
     */
    public storeJwtValidationPolicy(policy: IJwtValidationPolicy) {
        const policyKeys = Object.keys(policy.validation_policy);

        if (policyKeys.length === 0) {
            throw new Error(`Invalid policy keys provided.}`);
        }

        let existingJwtValidationPolicyData: Partial<IJwtValidationPolicyData> = this._store.get(policy.issuer) || {};

        // Merge and update each field
        policyKeys.forEach((key) => {
            const value = policy.validation_policy[key as keyof IJwtValidationPolicyData];

            if (value !== undefined) {
                (existingJwtValidationPolicyData as Record<string, string>)[key] = value;
            }
        });

        // Save the updated policy back to the store
        this._store.set(policy.issuer, existingJwtValidationPolicyData as IJwtValidationPolicyData);
        console.log(`JWT policy updated for issuer: ${policy.issuer}`);
    }

    /**
     * Deletes an existing policy for a given issuer.
     * @param issuer The key (issuer).
     */
    public deleteJwtValidationPolicy(issuer: string): void {
        if (!this._store.has(issuer)) {
            console.warn(`No existing policy found for issuer: ${issuer}`);
            return;
        }

        this._store.delete(issuer);
        console.log(`Policy deleted for issuer: ${issuer}`);
    }
}