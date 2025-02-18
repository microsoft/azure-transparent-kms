import * as ccfapp from "@microsoft/ccf-app";
import { IKeyReleasePolicyClaims } from "../policies/KeyReleaseClaimsPolicy";

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
    // Their is something not clear as per the checked in constitution claimType: ADD is the key
    // but refering to this file: https://github.com/microsoft/azure-transparent-kms/blob/f268aac6f4ea224123d0bb330c8f93722ec5fa1b/src/policies/KeyReleasePolicy.ts#L285
    // it appears to me claims is the Key, along with other operators
    // as a result for now just store claims as object on key claims
    // @yf23 to confirm and refactor this method as needed
    this._store.set(claimType, claims as IKeyReleasePolicyClaims);
    console.log(`KRP Updated claim(s) stored successfully for type: ${claimType}.`);
    };


  /**
 * Stores a claim(s) into the key-value store.
 * @param claimType The key type.
 * @param claims The single claim object (one or more fields from IClaims).
 */
  public storeIndividualClaim(claimType: string, claims: Partial<IKeyReleasePolicyClaims>): void {
    // const validKeys = new Set(Object.keys({} as IKeyReleasePolicyClaims));
    const claimsKeys = Object.keys(claims);

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
  public removeIndividualClaims(claimType: string, claims: Partial<IKeyReleasePolicyClaims>): void {
    const claimKeys = Object.keys(claims);

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