// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { ccf } from "@microsoft/ccf-app/global";
import { keyRotationPolicyMap } from "../repositories/Maps";

const keyRotationPolicyMapName = "public:kms.policies.key_rotation";

export class KeyRotationPolicy {
  static validate(policy: Record<string, any>): void {
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
    map: typeof keyRotationPolicyMap,
    policy: Record<string, any>): void {
    console.log(`Applying key rotation policy: ${JSON.stringify(policy)}`);

    const key = "key_rotation_policy";
    const keyBuf = ccf.strToBuf(key);
    const jsonItems = JSON.stringify(policy);
    const jsonItemsBuf = ccf.strToBuf(jsonItems);

    keyRotationPolicyMap.set(keyBuf, jsonItemsBuf);
    console.log(`Key rotation policy saved to ${keyRotationPolicyMapName}`);
  }
}