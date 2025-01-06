// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

actions.set(
  "set_settings_policy",
  new Action(
    function (args) {
      console.log(`[INFO] [scope=set_settings_policy] Check args: ${JSON.stringify(args)}`);
      checkType(args.settings_policy, "object", "settings_policy");
      checkType(args.settings_policy.service, "object", "service");

      // Check settings policy
      checkType(args.settings_policy.service.name, "string");
      checkType(args.settings_policy.service.description, "string");
      checkType(args.settings_policy.service.version, "string");
      checkType(args.settings_policy.service.debug, "boolean");
      console.log(`[INFO] [scope=set_settings_policy] Settings policy validation passed`);
    },
    function (args) {
      const settingsPolicyMapName = "public:ccf.gov.policies.settings";

      // Save policy in the KV
      const key = "settings_policy";
      const keyBuf = ccf.strToBuf(key);
      const jsonItems = JSON.stringify(args.settings_policy);
      const jsonItemsBuf = ccf.strToBuf(jsonItems);
      ccf.kv[settingsPolicyMapName].set(keyBuf, jsonItemsBuf);
      console.log(
        `[INFO] [scope=set_settings_policy] Settings policy ${jsonItems} saved in ${settingsPolicyMapName}`,
      );
    },
  ),
);
actions.set(
  "set_jwt_validation_policy",
  new Action(
    function (args) {
      console.log(
        `[INFO] [scope=set_jwt_validation_policy] Check args: ${JSON.stringify(args)}`,
      );
      checkType(args.issuer, "string", "issuer");
      checkType(args.validation_policy, "object", "validation_policy");

      // Check if issuer exists
      //if (!ccf.kv[validationPolicyMapName].has(args.issuer))  {
      //  throw new Error(``);
      //}

      // Check validation policy
      if (args.validation_policy) {
        Object.keys(args.validation_policy).forEach((key) => {
          if (Array.isArray(args.validation_policy[key])) {
            console.log(
              `[INFO] [scope=set_jwt_validation_policy] Validation policy: key ${key} is array = `,
              args.validation_policy[key],
            );
          } else {
            console.log(
              `[INFO] [scope=set_jwt_validation_policy] Validation policy: key ${key} = ${args.validation_policy[key]}`,
            );
            checkType(args.validation_policy[key], "string", key);
          }
        });
      }
    },
    function (args) {
      const validationPolicyMapName = "public:ccf.gov.policies.jwt_validation";

      const keyBuf = ccf.strToBuf(args.issuer);

      // Remove existing validation policy
      ccf.kv[validationPolicyMapName].delete(keyBuf);

      const jsonItems = JSON.stringify(args.validation_policy);
      const jsonItemsBuf = ccf.strToBuf(jsonItems);
      console.log(
        `[INFO] [scope=set_jwt_validation_policy] JWT validation policy item. Key: ${args.issuer}, value: ${jsonItems}`,
      );
      ccf.kv[validationPolicyMapName].set(keyBuf, jsonItemsBuf);
    },
  ),
);
