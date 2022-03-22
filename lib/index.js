/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

import { join, parse } from "node:path";
import { find, load } from "node-gyp-load";
import { Failure } from "@xan105/error";
import { exists } from "@xan105/fs";
import { dirname } from "@xan105/fs/path";
import { shouldStringNotEmpty } from "@xan105/is/assert";

const bindings = await find({
  name: "winVerifyTrust",
  dir: join(dirname(import.meta.url), "../"),
  prebuild: true
});

const { verifySignature } = load(bindings);

async function isSignedVerbose(filePath) {

  shouldStringNotEmpty(filePath);
  
  const allowed = [ '.exe', '.cab', '.dll', '.ocx', '.msi', '.msix', '.xpi' ];
  const ext = parse(filePath).ext;
  if (!allowed.includes(ext)) throw new Failure(`Accepted file types are: ${allowed.join(",")}`, "ERR_UNEXPECTED_FILE_TYPE");
  
  if (!await exists(filePath)) throw new Failure("Unable to locate target file", "ERR_NO_SUCH_FILE");

  return verifySignature(filePath);
}

async function isSigned(filePath) {
  const { signed } = await isSignedVerbose(filePath);
  return signed;
}

async function trustStatus(filePath) {
  const { message } = await isSignedVerbose(filePath);
  return message;
}

export { isSigned, trustStatus, isSignedVerbose };