import * as ccfapp from "@microsoft/ccf-app";
import { IKeyReleaseClaims } from "../policies/IKeyReleaseClaims";

// KeyReleaseClaimsPolicyStore class
export class KeyReleaseClaimsPolicyStore {
  private _store: ccfapp.TypedKvMap<string, IKeyReleaseClaims>;

  constructor(public nameOfMap: string) {
    this._store = ccfapp.typedKv(nameOfMap as string, ccfapp.string, ccfapp.json<IKeyReleaseClaims>());
  }

  public get store(): ccfapp.TypedKvMap<string, IKeyReleaseClaims> {
    return this._store;
  }

  /**
   * Stores a claim(s) into the key-value store.
   * @param type The key type.
   * @param claim The single claim object (one or more fields from IClaims).
   */
  public storeClaims(type: string, claims: Partial<IKeyReleaseClaims>): void {
    const validKeys = new Set(Object.keys({} as IKeyReleaseClaims));
    const claimsKeys = Object.keys(claims);

    if (claimsKeys.length === 0 || !claimsKeys.every((key) => validKeys.has(key))) {
      throw new Error(`Invalid claims provided. Allowed claims: ${Array.from(validKeys).join(", ")}`);
    }

    let existingClaims: Partial<IKeyReleaseClaims> = {};

    if (this._store.has(type)) {
      const storedClaims = this._store.get(type);
      if (storedClaims) {
        existingClaims = storedClaims;
      } else {
        throw new Error(`Unexpected undefined value for key: ${type}`);
      }
    } else {
      console.log(`KRP add ${type} => key: ${type} is new in the key release policy`);
    }

    // Store each claim correctly
    claimsKeys.forEach((key) => {
      const value = claims[key as keyof IKeyReleaseClaims];

      if (value !== undefined) {
        // Explicit type assertion ensures no `undefined` issue
        (existingClaims as Record<string, string | number | boolean>)[key] = value;
      }
    });

    // Save updated claims back to the store
    this._store.set(type, existingClaims as IKeyReleaseClaims);
    console.log(`KRP add ${type} => Updated claim(s) stored successfully.`);
  }

  /**
   * Removes claims from the key-value store.
   * @param type The key type.
   * @param claims The claims to remove.
   */
  public removeClaims(type: string, claims: Partial<IKeyReleaseClaims>): void {
    const validKeys = new Set(Object.keys({} as IKeyReleaseClaims));
    const claimKeys = Object.keys(claims);

    if (claimKeys.length === 0 || !claimKeys.every((key) => validKeys.has(key))) {
      throw new Error(`Invalid claims provided. Allowed claims: ${Array.from(validKeys).join(", ")}`);
    }

    let existingClaims: Partial<IKeyReleaseClaims> = {};

    if (this._store.has(type)) {
      const storedClaims = this._store.get(type);
      if (storedClaims) {
        existingClaims = storedClaims;
      } else {
        throw new Error(`Unexpected undefined value for key: ${type}`);
      }
    } else {
      console.log(`KRP remove ${type} => key: ${type} does not exist in the key release policy`);
      throw new Error(`The key ${type} does not exist in the key release policy.`);
    }

    // Remove only if the claim exists
    claimKeys.forEach((key) => {
      if (existingClaims[key as keyof IKeyReleaseClaims] !== undefined) {
        delete existingClaims[key as keyof IKeyReleaseClaims];
      }
    });

    this._store.set(type, existingClaims as IKeyReleaseClaims);
    console.log(`KRP remove ${type} => Updated claims after removal stored successfully.`);
  }

  /**
   * Fetches claims from the store.
   * @param type The key type to fetch.
   * @returns The claims object or null if not found.
   */
  public getClaims(type: string): IKeyReleaseClaims | null {
    if (this._store.has(type)) {
      const storedData = this._store.get(type);
      if (storedData) {
        return storedData as IKeyReleaseClaims;
      }
    }
    return null;
  }
}