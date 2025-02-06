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
   * @param type The key type.
   * @param claim The single claim object (one or more fields from IClaims).
   */
  public storeClaims(claims: Partial<IKeyReleasePolicyClaims>): void {
    const validKeys = new Set(Object.keys({} as IKeyReleasePolicyClaims));
    const claimsKeys = Object.keys(claims);

    if (claimsKeys.length === 0 || !claimsKeys.every((key) => validKeys.has(key))) {
      throw new Error(`Invalid claims provided. Allowed claims: ${Array.from(validKeys).join(", ")}`);
    }

    let existingClaims: Partial<IKeyReleasePolicyClaims> = {};

    // Store each claim correctly
    claimsKeys.forEach((key) => {
      const value = claims[key as keyof IKeyReleasePolicyClaims];

      if (value !== undefined) {
        // Explicit type assertion ensures no `undefined` issue
        (existingClaims as Record<string, string | number | boolean | object>)[key] = value;
      }

      // Save updated claims back to the store
      this._store.set(key, existingClaims as IKeyReleasePolicyClaims);
    });
    console.log(`KRP Updated claim(s) stored successfully.`);
  }

  /**
   * Removes claims from the key-value store.
   * @param claims The claims to remove.
   */
  public removeClaims(claims: Partial<IKeyReleasePolicyClaims>): void {
    const validKeys = new Set(Object.keys({} as IKeyReleasePolicyClaims));
    const claimKeys = Object.keys(claims);
  
    if (claimKeys.length === 0 || !claimKeys.every((key) => validKeys.has(key))) {
      throw new Error(`Invalid claims provided. Allowed claims: ${Array.from(validKeys).join(", ")}`);
    }
  
    // Directly delete claims from CCF KVMap
    claimKeys.forEach((key) => {
      this._store.delete(key as string);
      console.log(`KRP remove => Removed ${key} from CCF KVMap.`);
    });
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