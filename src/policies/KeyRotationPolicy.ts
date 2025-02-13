// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { KeyRotationPolicyStore } from "../repositories/KeyRotationPolicyStore";
import { IKeyRotationPolicy } from "./IKeyRotationPolicy";

// Lambda function to validate a key rotation policy
export const validateKeyRotationPolicy = (policy: IKeyRotationPolicy): void => {
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
};


const keyRotationPolicy: string = "key_rotation_policy";

// Lambda function to apply a key rotation policy
export const applyKeyRotationPolicy = (
  map: KeyRotationPolicyStore,
  policy: IKeyRotationPolicy
): void => {
  console.log(`Applying key rotation policy: ${JSON.stringify(policy)}`);

  map.storeRotationPolicy(keyRotationPolicy, policy);
  console.log(`Key rotation policy saved.`);
};

// Lambda function to retrieve the key rotation policy
export const getKeyRotationPolicyFromMap = (
  map: KeyRotationPolicyStore
): IKeyRotationPolicy | undefined => {
  console.log(`Get key rotation policy`);
  return map.getRotationPolicy(keyRotationPolicy);
};
