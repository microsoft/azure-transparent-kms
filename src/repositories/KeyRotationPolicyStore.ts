// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { IKeyRotationPolicy } from "../policies/IKeyRotationPolicy";

export class KeyRotationPolicyStore {

  private _store: ccfapp.TypedKvMap<string, IKeyRotationPolicy>;

  // Create an instance of the class KeyStore
  constructor(public nameOfMap: string) {
    this._store = ccfapp.typedKv(
      nameOfMap, 
      ccfapp.string,
      ccfapp.json<IKeyRotationPolicy>(),
    );
  }

  // Store key item with claims digest in the map
  public storeRotationPolicy(policy_name: string, policy: IKeyRotationPolicy) {
    // Clear Store before adding Single Rotation Policy
    this._store.clear();
    console.log(`Adding policy ${policy}`);
    this._store.set(policy_name, policy);
    console.log(`Get key rotation policy ${this._store.size}`);
  }

  public getRotationPolicy(policy_name: string): IKeyRotationPolicy | undefined {
    let result: IKeyRotationPolicy | undefined;
    // Iterate over the set and return the first (and only) value
    console.log(`Get key rotation policy ${this._store.size}`);
    result = this._store.get(policy_name);
    return result; // Return the captured value or undefined if the set is empty
  }
}