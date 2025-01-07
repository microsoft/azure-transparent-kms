 // Copyright (c) Microsoft Corporation.
 // Licensed under the MIT license.
 
 import * as ccfapp from "@microsoft/ccf-app";
 
 export class KeyReleasePolicyStore<K extends string, T> {
   private _store;
   private _claims = {
    "x-ms-attestation-type": "string",
    "x-ms-compliance-status": "string",
    "x-ms-policy-hash": "string",
    "vm-configuration-secure-boot": "boolean",
    "vm-configuration-secure-boot-template-id": "string",
    "vm-configuration-tpm-enabled": "boolean",
    "vm-configuration-vmUniqueId": "string",
    "x-ms-sevsnpvm-authorkeydigest": "string",
    "x-ms-sevsnpvm-bootloader-svn": "number",
    "x-ms-sevsnpvm-familyId": "string",
    "x-ms-sevsnpvm-guestsvn": "number",
    "x-ms-sevsnpvm-hostdata": "string",
    "x-ms-sevsnpvm-idkeydigest": "string",
    "x-ms-sevsnpvm-imageId": "string",
    "x-ms-sevsnpvm-is-debuggable": "boolean",
    "x-ms-sevsnpvm-launchmeasurement": "string",
    "x-ms-sevsnpvm-microcode-svn": "number",
    "x-ms-sevsnpvm-migration-allowed": "boolean",
    "x-ms-sevsnpvm-reportdata": "string",
    "x-ms-sevsnpvm-reportid": "string",
    "x-ms-sevsnpvm-smt-allowed": "boolean",
    "x-ms-sevsnpvm-snpfw-svn": "number",
    "x-ms-sevsnpvm-tee-svn": "number",
    "x-ms-sevsnpvm-vmpl": "number",
    "x-ms-ver": "string",
  };
 
   // Create an instance of the class KeyReleaseClaimStore
   constructor(public nameOfMap: string) {
     this._store = ccfapp.typedKv(nameOfMap, ccfapp.string, ccfapp.json<T>());
   }
 
   // Get the store
   public get store(): ccfapp.TypedKvMap<K, T> {
     return this._store;
   }

  // Store key item with claims digest in the map
  public storeClaims(type: string, claims: Record<string, any>): void {

    let items: Record<string, any> = {};

    // Check if the type exists in the map
    if (this._store.has(type as K)) {
      const itemsBuf = this._store.get(type as K);
      if (itemsBuf) {
        items = itemsBuf as Record<string, any>;
      } else {
        throw new Error(`Unexpected undefined value for key: ${type}`);
      }
    } else {
      console.log(`KRP add ${type} => key: ${type} is new in the key release policy`);
    }

    // Iterate over every claim
    Object.keys(claims).forEach((key) => {
      if (!this._claims[key]) {
        throw new Error(`KRP add ${type} => The claim ${key} is not an allowed claim.`);
      }
      let item = claims[key];
      // Ensure item is always an array
      if (!Array.isArray(item)) {
        item = [item];
      }

      if (items[key] !== undefined) {
        item.forEach((i) => {
          console.log(`KRP add ${type} => Adding ${i} to ${key}`);
          items[key].push(i);
        });
      } else {
        items[key] = item;
      }
    });

    // Save into KV
    const jsonItems = JSON.stringify(items);
    this._store.set(type as K, jsonItems as T);
    console.log(`KRP add ${type} => Updated claims stored successfully.`);
  }

  // Remove key item with claims digest from the map
  public removeClaims(type: string, claims: Record<string, any>): void {

    let items: Record<string, any> = {};

    if (this._store.has(type as K)) {
      const itemsBuf = this._store.get(type as K);
      if (itemsBuf) {
        items = itemsBuf as Record<string, any>;
      } else {
        throw new Error(`Unexpected undefined value for key: ${type}`);
      }
    } else {
      console.log(`KRP remove ${type} => key: ${type} does not exist in the key release policy`);
      throw new Error(`The key ${type} does not exist in the key release policy.`);
    }

    Object.keys(claims).forEach((key) => {
      if (!this._claims[key]) {
        throw new Error(`KRP remove ${type} => The claim ${key} is not an allowed claim.`);
      }
      let item = claims[key];
      if (!Array.isArray(item)) {
        item = [item];
      }

      if (items[key] !== undefined) {
        item.forEach((i) => {
          console.log(`KRP remove ${type} => Removing ${i} from ${key}`);
          items[key] = items[key].filter((value: any) => value !== i);
          if (items[key].length === 0) {
            delete items[key];
          }
        });
      } else {
        console.log(`KRP remove ${type} => Claim ${key} not found in the key release policy`);
        throw new Error(`The claim ${key} does not exist in the key release policy.`);
      }
    });

    const jsonItems = JSON.stringify(items);
    this._store.set(type as K, jsonItems as T);
    console.log(`KRP remove ${type} => Updated claims after removal stored successfully.`);
  }
 }