// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { IKeyRotationPolicy } from "../policies/IKeyRotationPolicy";

export class KeyRotationPolicyStore {
  private _store;

  // Create an instance of the class KeyStore
  constructor(public nameOfSet: string) {
    this._store = ccfapp.typedKvSet(
      nameOfSet,
      ccfapp.json<IKeyRotationPolicy>(),
    );
  }

  // Get the store
  private get store(): ccfapp.TypedKvSet<IKeyRotationPolicy> {
    return this._store;
  }

  // Store key item with claims digest in the map
  public storeRotationPolicy(policy: IKeyRotationPolicy) {
    // Clear Store before adding Single Rotation Policy
    this.store.clear();
    this.store.add(policy);
  }

  public getRotationPolicy(): IKeyRotationPolicy | undefined {
    let result: IKeyRotationPolicy | undefined;
    // Iterate over the set and return the first (and only) value
    this.store.forEach((policy) => {
      result = policy; // Capture the first and only policy
    });

    return result; // Return the captured value or undefined if the set is empty
  }
}