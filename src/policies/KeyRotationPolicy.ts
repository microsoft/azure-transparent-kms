// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { keyRotationPolicySet, keyRotationSetName as keyRotationPolicySetName } from "../repositories/Maps";
import { IKeyRotationPolicy } from "./IKeyRotationPolicy";

export class KeyRotationPolicy {

  static validate(policy: IKeyRotationPolicy): void {
    console.log(`Validating key rotation policy: ${JSON.stringify(policy)}`);

    if (typeof policy !== "object" || policy === null) {
      throw new Error("Key rotation policy must be an object.");
    }

    if (typeof policy.rotation_interval_seconds !== "number") {
      throw new Error("rotation_interval_seconds must be a number.");
    }

    if (typeof policy.grace_period_seconds !== "number") {
      throw new Error("grace_period_seconds must be a number.");
    }

    console.log(`Key rotation policy validation passed.`);
  }

  static apply(
    map: typeof keyRotationPolicySet,
    policy: IKeyRotationPolicy): void {
    console.log(`Applying key rotation policy: ${JSON.stringify(policy)}`);

    keyRotationPolicySet.storeRotationPolicy(policy);
    console.log(`Key rotation policy saved to ${keyRotationPolicySetName}`);
  }

  static get(
    map: typeof keyRotationPolicySet): IKeyRotationPolicy | undefined {
    console.log(`Get key rotation policy from ${keyRotationPolicySetName}}`);
    const keyRotationPolicy = keyRotationPolicySet.getRotationPolicy();
    return keyRotationPolicy
  }
}