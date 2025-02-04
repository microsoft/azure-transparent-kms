import * as ccfapp from "@microsoft/ccf-app";
import { IClaims } from "../policies/IKeyReleaseClaims";


// KeyReleaseClaimsPolicyStore class
export class KeyReleaseClaimsPolicyStore<K extends string, T> {
  private _store: ccfapp.TypedKvMap<K, T>;

  constructor(public nameOfMap: string) {
    this._store = ccfapp.typedKv(nameOfMap, ccfapp.string, ccfapp.json<T>());
  }

  public get store(): ccfapp.TypedKvMap<K, T> {
    return this._store;
  }

  // Store key item with claims digest in the map
  public storeClaims(type: string, claims: Partial<IClaims>): void {
    let items: Partial<IClaims> = {};

    if (this._store.has(type as K)) {
      const itemsBuf = this._store.get(type as K);
      if (itemsBuf) {
        items = itemsBuf as Partial<IClaims>;
      } else {
        throw new Error(`Unexpected undefined value for key: ${type}`);
      }
    } else {
      console.log(`KRP add ${type} => key: ${type} is new in the key release policy`);
    }

    Object.keys(claims).forEach((key) => {
      if (!(key in {} as IClaims)) {
        throw new Error(`KRP add ${type} => The claim ${key} is not an allowed claim.`);
      }

      let item = claims[key as keyof IClaims];
      if (!Array.isArray(item)) {
        item = [item] as any;
      }

      if (items[key as keyof IClaims] !== undefined) {
        (item as any[]).forEach((i) => {
          console.log(`KRP add ${type} => Adding ${i} to ${key}`);
          (items[key as keyof IClaims] as any[]).push(i);
        });
      } else {
        items[key as keyof IClaims] = item as any;
      }
    });

    this._store.set(type as K, JSON.stringify(items) as T);
    console.log(`KRP add ${type} => Updated claims stored successfully.`);
  }

  // Remove key item with claims digest from the map
  public removeClaims(type: string, claims: Partial<IClaims>): void {
    let items: Partial<IClaims> = {};

    if (this._store.has(type as K)) {
      const itemsBuf = this._store.get(type as K);
      if (itemsBuf) {
        items = itemsBuf as Partial<IClaims>;
      } else {
        throw new Error(`Unexpected undefined value for key: ${type}`);
      }
    } else {
      console.log(`KRP remove ${type} => key: ${type} does not exist in the key release policy`);
      throw new Error(`The key ${type} does not exist in the key release policy.`);
    }

    Object.keys(claims).forEach((key) => {
      if (!(key in {} as IClaims)) {
        throw new Error(`KRP remove ${type} => The claim ${key} is not an allowed claim.`);
      }

      let item = claims[key as keyof IClaims];
      if (!Array.isArray(item)) {
        item = [item] as any;
      }

      if (items[key as keyof IClaims] !== undefined) {
        (item as any[]).forEach((i) => {
          console.log(`KRP remove ${type} => Removing ${i} from ${key}`);
          items[key as keyof IClaims] = (items[key as keyof IClaims] as any[]).filter(
            (value: any) => value !== i
          ) as any;
          if ((items[key as keyof IClaims] as any[]).length === 0) {
            delete items[key as keyof IClaims];
          }
        });
      } else {
        console.log(`KRP remove ${type} => Claim ${key} not found in the key release policy`);
        throw new Error(`The claim ${key} does not exist in the key release policy.`);
      }
    });

    this._store.set(type as K, JSON.stringify(items) as T);
    console.log(`KRP remove ${type} => Updated claims after removal stored successfully.`);
  }
}