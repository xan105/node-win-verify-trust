/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

import { join, extname } from "node:path";
import { find, load } from "node-gyp-load";
import { Failure, errorLookup } from "@xan105/error";
import { shouldStringNotEmpty } from "@xan105/is/assert";
import { dirname } from "@xan105/fs/path";
import { exists } from "@xan105/fs";

//Load bindings
const bindings = await find({
  name: "winVerifyTrust",
  dir: join(dirname(import.meta.url), "../"),
  prebuild: true
});

const { verifySignature } = load(bindings);

async function verifyTrust(filePath) {

  shouldStringNotEmpty(filePath);
  
  const allowed = [ ".exe", ".cab", ".dll", ".ocx", ".msi", ".msix", ".xpi", ".ps1" ];
  if (!allowed.includes(extname(filePath)))
    throw new Failure(`Accepted file types are: ${allowed.join(",")}`, 1);
  if (!await exists(filePath))
    throw new Failure("No such file", "ENOENT");

  let result = {}, error;
  do{
    const status = verifySignature(filePath);
    if (status === 0) { 
      result.trusted = true;
      result.message = "The file is signed and the signature was verified";
      error = "ERROR_SUCCESS";
    } else {
      const [ message, code ] = errorLookup(status);
      result.trusted = false;
      result.message = message;
      error = code;
    }
  }while(error === "CRYPT_E_FILE_ERROR");
  
  return result;
}

async function isSigned(filePath) {
  try{
    const { trusted } = await verifyTrust(filePath);
    return trusted;
  }catch{
    return false;
  }
}

export { 
  verifyTrust,
  isSigned
};