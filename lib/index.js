/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

import { join, extname } from "node:path";
import { find, load } from "node-gyp-load";
import { Failure, errorLookup } from "@xan105/error";
import { isString, isStringNotEmpty, isObjLike } from "@xan105/is";
import { shouldStringNotEmpty, shouldObjLike } from "@xan105/is/assert";
import { dirname, resolve } from "@xan105/fs/path";
import { exists } from "@xan105/fs";

//Load bindings
const bindings = await find({
  name: "winVerifyTrust",
  dir: join(dirname(import.meta.url), "../"),
  prebuild: true
});

const { 
  verifySignature, 
  certificateInfo 
} = load(bindings);

const allowed = [ ".exe", ".cab", ".dll", ".ocx", ".msi", ".msix", ".xpi", ".ps1" ];

async function verifyTrust(filePath) {

  shouldStringNotEmpty(filePath);
  
  if (!allowed.includes(extname(filePath)))
    throw new Failure(`Accepted file types are: ${allowed.join(",")}`, 1);
  if (!await exists(filePath))
    throw new Failure("No such file", { code: "ENOENT", info: filePath });

  let result = {}, error;
  do{
    const status = verifySignature(resolve(filePath));
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
  } while(error === "CRYPT_E_FILE_ERROR");
  
  return result;
}

async function getCertificate(filePath){
  
  shouldStringNotEmpty(filePath);
  
  if (!allowed.includes(extname(filePath)))
    throw new Failure(`Accepted file types are: ${allowed.join(",")}`, 1);
  if (!await exists(filePath))
    throw new Failure("No such file", { code: "ENOENT", info: filePath });

  let error, certificate;
  do {
    certificate = {};
    const result = certificateInfo(resolve(filePath), certificate);
    if (result !== 0) 
    { 
      const [ message, code ] = errorLookup(result);
      if(code !== "CRYPT_E_NO_MATCH") throw new Failure(message, code);
      error = code; 
    } 
    else 
    {
      shouldObjLike(certificate, {
        programName: [isString, [], { optional: true }],
        publisherLink: [isString, [], { optional: true }],
        infoLink: [isString, [], { optional: true }],
        signer: [isObjLike, [{
          issuer: [isString, [], { optional: true }],
          subject: [isString, [], { optional: true }]
        }]],
        timestamp: [isObjLike, [{
          issuer: [isString, [], { optional: true }],
          subject: [isString, [], { optional: true }]
        }]],
      }, new Failure("Unexpected result from the native addon !", {
        code: 0,
        info: { result, certificate }
      }));
      error = "ERROR_SUCCESS";
    }
  } while(error === "CRYPT_E_NO_MATCH");
  
  return certificate;
}

async function isSigned(filePath, name = null) {
  try{
    const { trusted } = await verifyTrust(filePath);
    if(isStringNotEmpty(name) && trusted){
      const { signer } = await getCertificate(filePath);
      return signer.subject?.toLowerCase() === name.toLowerCase();
    } else {
      return trusted;
    }
  }catch{
    return false;
  }
}

export { 
  verifyTrust,
  getCertificate,
  isSigned,
};