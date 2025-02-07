// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

export class AzureVMKeyReleasePolicyClaims {
  secureboot?: boolean;
  "x-ms-attestation-type"?: string;
  "x-ms-azurevm-os-provisioning.node-policy-identity.eventVersion"?: number;
  "x-ms-azurevm-os-provisioning.node-policy-identity.policyId"?: string;
  "x-ms-azurevm-os-provisioning.node-policy-identity.signer"?: string;
  "x-ms-azurevm-os-provisioning.node-policy-identity.svn"?: number;
  "x-ms-azurevm-os-provisioning.os-image-identity.diskId"?: string;
  "x-ms-azurevm-os-provisioning.os-image-identity.eventVersion"?: number;
  "x-ms-azurevm-os-provisioning.os-image-identity.signer"?: string;
  "x-ms-azurevm-os-provisioning.os-image-identity.svn"?: number;
  "x-ms-azurevm-attestation-protocol-ver"?: string;
  "x-ms-azurevm-attested-pcrs"?: number[];
  "x-ms-azurevm-bootdebug-enabled"?: boolean;
  "x-ms-azurevm-dbvalidated"?: boolean;
  "x-ms-azurevm-dbxvalidated"?: boolean;
  "x-ms-azurevm-debuggersdisabled"?: boolean;
  "x-ms-azurevm-default-securebootkeysvalidated"?: boolean;
  "x-ms-azurevm-elam-enabled"?: boolean;
  "x-ms-azurevm-flightsigning-enabled"?: boolean;
  "x-ms-azurevm-hvci-policy"?: number;
  "x-ms-azurevm-hypervisordebug-enabled"?: boolean;
  "x-ms-azurevm-is-windows"?: boolean;
  "x-ms-azurevm-kerneldebug-enabled"?: boolean;
  "x-ms-azurevm-osbuild"?: string;
  "x-ms-azurevm-osdistro"?: string;
  "x-ms-azurevm-ostype"?: string;
  "x-ms-azurevm-osversion-major"?: number;
  "x-ms-azurevm-osversion-minor"?: number;
  "x-ms-azurevm-signingdisabled"?: boolean;
  "x-ms-azurevm-testsigning-enabled"?: boolean;
  "x-ms-azurevm-vmid"?: string;
  "x-ms-isolation-tee"?: object;
  "x-ms-policy-hash"?: string;
  "x-ms-runtime"?: {
    "client-payload"?: {
      a?: string;
    };
    keys?: object;
  };
  "x-ms-ver"?: string;
}