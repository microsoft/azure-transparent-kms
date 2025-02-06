import * as ccfapp from "@microsoft/ccf-app";
import { IKeyReleasePolicyClaims } from "../policies/IKeyReleasePolicyClaims";

// KeyReleaseClaimsPolicyStore class
export class KeyReleaseClaimsPolicyStore {
  private _store: ccfapp.TypedKvMap<string, IKeyReleasePolicyClaims>;

  constructor(public nameOfMap: string) {
    this._store = ccfapp.typedKv(nameOfMap as string, ccfapp.string, ccfapp.json<IKeyReleasePolicyClaims>());
  }

  public get store(): ccfapp.TypedKvMap<string, IKeyReleasePolicyClaims> {
    return this._store;
  }

  /**
 * Stores a claim(s) into the key-value store.
 * @param claimType The key type.
 * @param claims The single claim object (one or more fields from IClaims).
 */
  public storeClaims(claimType: string, claims: Partial<IKeyReleasePolicyClaims>): void {
    const validKeys = new Set(Object.keys({} as IKeyReleasePolicyClaims));
    const claimsKeys = Object.keys(claims);

    if (claimsKeys.length === 0 || !claimsKeys.every((key) => validKeys.has(key))) {
      throw new Error(`Invalid claims provided. Allowed claims: ${Array.from(validKeys).join(", ")}`);
    }

    // Fetch existing claims from the store for this type
    let existingClaims: Partial<IKeyReleasePolicyClaims> = this._store.get(claimType) || {};

    // Store each claim correctly
    claimsKeys.forEach((key) => {
      const value = claims[key as keyof IKeyReleasePolicyClaims];

      if (value !== undefined) {
        // Explicit type assertion ensures no `undefined` issue
        (existingClaims as Record<string, string | number | boolean | object>)[key] = value;
      }
    });

    // Save updated claims back to the store with the type as the key
    this._store.set(claimType, existingClaims as IKeyReleasePolicyClaims);
    console.log(`KRP Updated claim(s) stored successfully for type: ${claimType}.`);
  }

  /**
   * Removes claims from the key-value store for a specific type.
   * @param claimType The key type.
   * @param claims The claims to remove.
   */
  public removeClaims(claimType: string, claims: Partial<IKeyReleasePolicyClaims>): void {
    const validKeys = new Set(Object.keys({} as IKeyReleasePolicyClaims));
    const claimKeys = Object.keys(claims);

    if (claimKeys.length === 0 || !claimKeys.every((key) => validKeys.has(key))) {
      throw new Error(`Invalid claims provided. Allowed claims: ${Array.from(validKeys).join(", ")}`);
    }

    // Fetch existing claims for this type
    let existingClaims: Partial<IKeyReleasePolicyClaims> = this._store.get(claimType) || {};

    // Remove only specified claims
    claimKeys.forEach((key) => {
      if (existingClaims[key as keyof IKeyReleasePolicyClaims] !== undefined) {
        delete existingClaims[key as keyof IKeyReleasePolicyClaims];
        console.log(`KRP remove => Removed ${key} from claims under type: ${claimType}`);
      }
    });

    // If no claims remain, delete the type entry from the store
    if (Object.keys(existingClaims).length === 0) {
      this._store.delete(claimType);
      console.log(`KRP remove => No claims left, removed type: ${claimType} from CCF KVMap.`);
    } else {
      // Otherwise, update the KV store with remaining claims
      this._store.set(claimType, existingClaims as IKeyReleasePolicyClaims);
      console.log(`KRP remove => Updated claims for type: ${claimType} in CCF KVMap.`);
    }
  }


  /**
   * Fetches claims from the store.
   * @param type The key type to fetch.
   * @returns The claims object or null if not found.
   */
  public getClaims(type: string): IKeyReleasePolicyClaims | null {
    if (this._store.has(type)) {
      const storedData = this._store.get(type);
      if (storedData) {
        return storedData as IKeyReleasePolicyClaims;
      }
    }
    return null;
  }
}