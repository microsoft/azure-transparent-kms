import { ccf } from "@microsoft/ccf-app/global";
import { keyReleasePolicyMap } from "../repositories/Maps";

const keyReleaseMapName = "public:ccf.gov.policies.key_release";
const CLAIMS = {
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

export class KeyReleasePolicyClaims {

    static add(
        map: typeof keyReleasePolicyMap,
        type: string,
        claims: Record<string, any>,
    ): void {
        let items: Record<string, any> = {};

        // Get all claims for the type from the KV
        const keyBuf = ccf.strToBuf(type);
        if (ccf.kv[keyReleaseMapName].has(keyBuf)) {
            const itemsBuf = ccf.kv[keyReleaseMapName].get(keyBuf);
            if (itemsBuf) { // Ensure itemsBuf is not undefined
                items = JSON.parse(ccf.bufToStr(itemsBuf));
            } else {
                throw new Error(`Unexpected undefined value for key: ${type}`);
            }
        } else {
            console.log(`KRP add ${type} => key: ${type} is new in the key release policy`);
        }

        // Iterate over every claim
        Object.keys(claims).forEach((key) => {
            if (!CLAIMS[key]) {
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
        const jsonItemsBuf = ccf.strToBuf(jsonItems);
        ccf.kv[keyReleaseMapName].set(keyBuf, jsonItemsBuf);
        console.log(`KRP add ${type} => Updated claims: ${jsonItems}`);
    }

    static remove(
        map: typeof keyReleasePolicyMap,
        type: string,
        claims: Record<string, any>,
    ): void {
        let items: Record<string, any> = {};
        console.log(`Remove claims from key release policy for ${type}: ${JSON.stringify(claims)}`);

        // Get all claims for the type from the KV
        const keyBuf = ccf.strToBuf(type);
        if (ccf.kv[keyReleaseMapName].has(keyBuf)) {
            const itemsBuf = ccf.kv[keyReleaseMapName].get(keyBuf);
            if (itemsBuf) {
                items = JSON.parse(ccf.bufToStr(itemsBuf));
            } else {
                throw new Error(`Unexpected undefined value for key: ${type}`);
            }
        } else {
            console.log(`KRP remove ${type} => key: ${type} does not exist in the key release policy`);
            throw new Error(`The key ${type} does not exist in the key release policy.`);
        }

        // Iterate over every claim
        Object.keys(claims).forEach((key) => {
            if (!CLAIMS[key]) {
                throw new Error(`KRP remove ${type} => The claim ${key} is not an allowed claim.`);
            }
            let item = claims[key];
            // Ensure item is always an array
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

        // Save into KV
        console.log(`KRP remove ${type} => items: ${JSON.stringify(items)}`);
        const jsonItems = JSON.stringify(items);
        const jsonItemsBuf = ccf.strToBuf(jsonItems);
        ccf.kv[keyReleaseMapName].set(keyBuf, jsonItemsBuf);
    }
}
