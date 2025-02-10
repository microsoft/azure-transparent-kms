// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { readdirSync, statSync, readFileSync, writeFileSync } from "fs";
import { join, posix, sep } from "path";

const args = process.argv.slice(2);
const rootDir = args[0];

const metadataPath = join(rootDir, "app.json");

// Step 1: Read the copied `app.json` in `dist/`
const metadata = JSON.parse(readFileSync(metadataPath, "utf-8"));

// Step 2: Check if the environment flag `EXCLUDE_ROTATION_POLICY` is set
let excludeAPPTableEndpts = process.env.EXCLUDE_APP_TABLE_ENDPTS === "true";

console.log(`EXCLUDE_APP_TABLE_ENDPT is set to: ${excludeAPPTableEndpts}`);

// Step 3: Remove specific endpoints from `app.json` if the flag is enabled
if (excludeAPPTableEndpts && metadata.endpoints) {
  const excludeAPPTableEndpts = ["/setJwtValidationPolicy", "/removeJwtValidationPolicy", "/setKeyReleasePolicyClaims", "/getKeyReleasePolicyClaims", "/getKeyRotationPolicy", "/setKeyRotationPolicy"];

  excludeAPPTableEndpts.forEach((endpoint) => {
    if (metadata.endpoints[endpoint]) {
      console.log(`Removing endpoint: ${endpoint}`);
      delete metadata.endpoints[endpoint];
    }
  });

  // Step 4: Write the modified `app.json` back to `dist/`
  writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
  console.log(`Updated app.json saved in ${metadataPath}`);
}

// Step 5: Proceed with normal bundle creation
const getAllFiles = function (dirPath, arrayOfFiles) {
  arrayOfFiles = arrayOfFiles || [];
  const files = readdirSync(dirPath);
  for (const file of files) {
    const filePath = join(dirPath, file);
    if (statSync(filePath).isDirectory()) {
      arrayOfFiles = getAllFiles(filePath, arrayOfFiles);
    } else {
      arrayOfFiles.push(filePath);
    }
  }
  return arrayOfFiles;
};

const removePrefix = function (s, prefix) {
  return s.substr(prefix.length).split(sep).join(posix.sep);
};

const srcDir = join(rootDir, "src");
const allFiles = getAllFiles(srcDir);

// Define modules for the bundle
const toTrim = srcDir + "/";
const modules = allFiles.map((filePath) => ({
  name: removePrefix(filePath, toTrim),
  module: readFileSync(filePath, "utf-8"),
}));

// Write the final `bundle.json`
const bundlePath = join(rootDir, "bundle.json");
const bundle = {
  metadata: metadata,
  modules: modules,
};

console.log(
  `Writing bundle containing ${modules.length} modules to ${bundlePath}`
);
writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));