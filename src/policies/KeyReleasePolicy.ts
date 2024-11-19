// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import { IKeyReleasePolicy, KeyReleasePolicyType } from "./IKeyReleasePolicy";
import { IKeyReleasePolicySnpProps } from "./IKeyReleasePolicySnpProps";
import { Logger, LogContext } from "../utils/Logger";
import { ServiceResult } from "../utils/ServiceResult";
import { IAttestationReport } from "../attestation/ISnpAttestationReport";
import { KmsError } from "../utils/KmsError";

export class KeyReleasePolicy implements IKeyReleasePolicy {
  public type = KeyReleasePolicyType.ADD;
  public claims = {
    "x-ms-attestation-type": ["snp"],
  };

  private static checkSubset(//Check if o1 is a subset of o2
    o1: number | string | boolean | Record<string, any>,
    o2: number | string | boolean | Record<string, any>
  ): boolean {
    // If both values are primitives, compare them directly
    if (o1 === null || o2 === null || typeof o1 !== 'object' || typeof o2 !== 'object') {
      // Ensure neither is an object
      if (typeof o1 === 'object' || typeof o2 === 'object') {
        return false;
      }
      // Both should be primities, compare them directly
      return o1.toString() === o2.toString();
    }
    
    // Both values are objects; compare keys
    for (const key in o1) {
      if (o2.hasOwnProperty(key)) {
        if (!KeyReleasePolicy.checkSubset(o1[key], o2[key])) {
          return false;
        }
      } else {
        // If a key in o1 does not exist in o2, return false
        return false;
      }
    }
  
    // All checks passed, return true
    return true;
  }

  private static checkValuesLte( //Check if all values in o1 are smaller than or equal to the corresponding values in o2
    type: string,
    o1: number | string | Record<string, any>, 
    o2: number | string | Record<string, any>
  ): boolean 
  {
    // Helper to compare primitive values
    const comparePrimitives = (a: number | string, b: number | string): boolean => {
    const numA = typeof a === 'string' ? parseFloat(a) : a;
    const numB = typeof b === 'string' ? parseFloat(b) : b;
    if (isNaN(numA) || isNaN(numB)) return false;
    return type === "gte" ? numB >= numA : numB > numA;
    };

    // If either value is null or not an object, compare primitives directly
    if (o1 === null || o2 === null || typeof o1 !== 'object' || typeof o2 !== 'object') {
      // Ensure neither is an object
      if (typeof o1 === 'object' || typeof o2 === 'object') return false;
      
      // Both should be primities, compare them directly
      return comparePrimitives(o1 as number | string, o2 as number | string);
    }
    
    // Both are objects, we compare keys
    for (let key in o1) {
      if (o2.hasOwnProperty(key)) {
          if (!KeyReleasePolicy.checkValuesLte(type, o1[key], o2[key])) {
            return false;
          }
      }  
      else {
        // If key in o1 does not exist in o2, return false
        return false;
      }
    }
    // All checks passed, return true
    return true;
  }

  private static validateKeyReleasePolicyClaims(
    keyReleasePolicyClaims: IKeyReleasePolicySnpProps,
    attestationClaims: IAttestationReport,
    logContext?: LogContext,
  ): ServiceResult<string | IAttestationReport> {
    if (
      keyReleasePolicyClaims === null ||
      keyReleasePolicyClaims === undefined
    ) {
      return ServiceResult.Failed<string>(
        { errorMessage: "Missing key release policy" },
        500,
        logContext,
      );
    }
    if (attestationClaims === null || attestationClaims === undefined) {
      return ServiceResult.Failed<string>(
        { errorMessage: "Missing attestation claims" },
        500,
        logContext,
      );
    }

    for (let inx = 0; inx < Object.keys(keyReleasePolicyClaims).length; inx++) {
      const key = Object.keys(keyReleasePolicyClaims)[inx];

      // check if key is in attestation
      const attestationValue = attestationClaims[key];
      const policyValue = keyReleasePolicyClaims[key];
      const isUndefined = typeof attestationValue === "undefined";
      Logger.debug(
        `Checking key ${key}, typeof attestationValue: ${typeof attestationValue}, isUndefined: ${isUndefined}, attestation value: ${attestationValue}, policyValue: ${policyValue}`,
        logContext
      );
      if (isUndefined) {
        return ServiceResult.Failed<string>(
          { errorMessage: `Missing claim in attestation: ${key}` },
          400,
          logContext,
        );
      }
      if (
        policyValue.filter((p) => {
          Logger.debug(`Check if policy value ${p} === ${attestationValue}`, logContext);
          return KeyReleasePolicy.checkSubset(p, attestationValue);
        }).length === 0
      ) {
        return ServiceResult.Failed<string>(
          {
            errorMessage: `Attestation claim ${key}, value ${attestationValue} does not match policy values: ${policyValue}`,
          },
          400,
          logContext,
        );
      }
    }
    return ServiceResult.Succeeded<IAttestationReport>(attestationClaims, undefined, logContext);
  }

  private static validateKeyReleasePolicyOperators(
    type: string,
    keyReleasePolicyClaims: IKeyReleasePolicySnpProps,
    attestationClaims: IAttestationReport,
    logContext?: LogContext,
  ): ServiceResult<string | IAttestationReport> {
    if (
      keyReleasePolicyClaims === null ||
      keyReleasePolicyClaims === undefined
    ) {
      return ServiceResult.Failed<string>(
        { errorMessage: "Missing key release policy" },
        500,
        logContext,
      );
    }
    if (attestationClaims === null || attestationClaims === undefined) {
      return ServiceResult.Failed<string>(
        { errorMessage: "Missing attestation claims" },
        500,
        logContext,
      );
    }

    for (let inx = 0; inx < Object.keys(keyReleasePolicyClaims).length; inx++) {
      const key = Object.keys(keyReleasePolicyClaims)[inx];

      // check if key is in attestation
      let attestationValue = attestationClaims[key];
      let policyValue = keyReleasePolicyClaims[key];


      const isUndefined = typeof attestationValue === "undefined";
      Logger.debug(
        `Checking key ${key}, typeof attestationValue: ${typeof attestationValue}, isUndefined: ${isUndefined}, attestation value: ${attestationValue}, policyValue: ${policyValue}`,
        logContext
      );
      if (isUndefined) {
        return ServiceResult.Failed<string>(
          {
            errorMessage: `Missing claim in attestation: ${key} for operator type ${type}`,
          },
          400,
          logContext,
        );
      }
      if (policyValue === null || policyValue === undefined) {
        return ServiceResult.Failed<string>(
          {
            errorMessage: `Missing policy value for claim ${key} for operator type ${type}`,
          },
          500,
          logContext
        );
      }

      Logger.info(
        `Checking if attestation value ${attestationValue} is greater than (or equal) to policy value ${policyValue}`,
        logContext,
      );
      if (!KeyReleasePolicy.checkValuesLte(type, policyValue, attestationValue)) {
        return ServiceResult.Failed<string>(
          {
            errorMessage: `Attestation claim ${key}, value ${attestationValue} is not greater than (or equal) to policy value ${policyValue}`,
          },
          400,
          logContext,
        );
      }
    }
    return ServiceResult.Succeeded<IAttestationReport>(attestationClaims, undefined, logContext);
  }

  public static validateKeyReleasePolicy(
    keyReleasePolicy: IKeyReleasePolicy,
    attestationClaims: IAttestationReport,
    logContextIn?: LogContext,
  ): ServiceResult<string | IAttestationReport> {
    const logContext = (logContextIn?.clone() || new LogContext()).appendScope("validateKeyReleasePolicy");
    // claims are mandatory
    if (Object.keys(keyReleasePolicy.claims).length === 0) {
      return ServiceResult.Failed<string>(
        {
          errorMessage:
            "The claims in the key release policy are missing. Please propose a new key release policy",
        },
        400,
        logContext,
      );
    }

    // Check claims
    let policyValidationResult =
      KeyReleasePolicy.validateKeyReleasePolicyClaims(
        keyReleasePolicy.claims,
        attestationClaims,
        logContext
      );
    if (!policyValidationResult.success) {
      return policyValidationResult;
    }

    // Check operators gte and gt
    if (keyReleasePolicy.gte !== null && keyReleasePolicy.gte !== undefined) {
      Logger.info(`Validating gte operator`, logContext, keyReleasePolicy.gte);
      policyValidationResult =
        KeyReleasePolicy.validateKeyReleasePolicyOperators(
          "gte",
          keyReleasePolicy.gte,
          attestationClaims,
          logContext
        );
    }
    if (!policyValidationResult.success) {
      return policyValidationResult;
    }

    if (keyReleasePolicy.gt !== null && keyReleasePolicy.gt !== undefined) {
      Logger.info(`Validating gt operator`, logContext, keyReleasePolicy.gt);
      policyValidationResult =
        KeyReleasePolicy.validateKeyReleasePolicyOperators(
          "gt",
          keyReleasePolicy.gt,
          attestationClaims,
          logContext
        );
    }

    return policyValidationResult;
  }

  /**
   * Retrieves the key release policy from a key release policy map.
   * @param keyReleasePolicyMap - The key release policy map.
   * @returns The key release policy as an object.
   */
  public static getKeyReleasePolicyFromMap = (
    keyReleasePolicyMap: ccfapp.KvMap,
    logContextIn?: LogContext,
  ): IKeyReleasePolicy => {
    const logContext = (logContextIn?.clone() || new LogContext()).appendScope("getKeyReleasePolicyFromMap");
    const keyReleasePolicy: IKeyReleasePolicy = {
      type: KeyReleasePolicyType.ADD,
      claims: {},
    };

    [
      { kvkey: "claims", optional: false },
      { kvkey: "gte", optional: true },
      { kvkey: "gt", optional: true },
    ].forEach((kv) => {
      const kvKey = kv.kvkey;
      const kvKeyBuf = ccf.strToBuf(kvKey);
      const kvValueBuf = keyReleasePolicyMap.get(kvKeyBuf);
      if (!kvValueBuf) {
        if (!kv.optional) {
          throw new KmsError(`Key release policy ${kvKey} not found in the key release policy map`, logContext);
        }
      } else {
        let kvValue = ccf.bufToStr(kvValueBuf!);
        try {
          keyReleasePolicy[kvKey] = JSON.parse(
            kvValue,
          ) as IKeyReleasePolicySnpProps;
        } catch (error) {
          throw new KmsError(`Key release policy ${kvKey} is not a valid JSON object: ${kvValue}`, logContext);
        }
      }
    });

    Logger.info(`Resulting key release policy: `, logContext, keyReleasePolicy);
    return keyReleasePolicy;
  };
}
