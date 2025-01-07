// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { ccf } from "@microsoft/ccf-app/global";
import { keyRotationMapName, keyRotationPolicyMap } from "../repositories/Maps";
import { IKeyRotationPolicy } from "./IKeyRotationPolicy";
import { Logger, LogContext } from "../utils/Logger";
import { KmsError } from "../utils/KmsError";


export class KeyRotationPolicy {

    private static readonly logContext = new LogContext().appendScope("KeyRotationPolicy");
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
    console.log(`Key rotation policy saved to ${keyRotationMapName}`);
  }

  static get(
    map: typeof keyRotationPolicyMap): IKeyRotationPolicy | undefined {
    console.log(`Get key rotation policy from ${keyRotationMapName}}`);

    const key = "key_rotation_policy";
    const keyBuf = ccf.strToBuf(key);

    const keyRotationPolicy = keyRotationPolicyMap.get(keyBuf);

    const keyRotationPolicyStr = keyRotationPolicy ? ccf.bufToStr(keyRotationPolicy) : undefined;
    console.log(`Key rotation policy saved to ${keyRotationMapName}`);

    let keyRotationPolicyResult: IKeyRotationPolicy | undefined;
    if (!keyRotationPolicyStr) {
      Logger.warn(`No settings policy found, using default settings`, KeyRotationPolicy.logContext);
    } else {
      try {
        keyRotationPolicyResult = JSON.parse(keyRotationPolicyStr) as IKeyRotationPolicy;
      } catch {
        const error = `Failed to parse settings policy: ${keyRotationPolicyStr}`;
        Logger.error(error, KeyRotationPolicy.logContext);
        throw new KmsError(error, KeyRotationPolicy.logContext);
      }
    }

    return keyRotationPolicyResult
  }
}