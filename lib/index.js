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
  
  const failsafe = Date.now() + 1500;
  const result = {};
  let error, outatime;
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
  } while(
    error === "CRYPT_E_FILE_ERROR" && 
    (outatime = Date.now() >= failsafe) === false
  )
    /*
    Because this Windows API is horrible to work with and fails many time I/O wise.
    To make it somehow reliable we have to do this horrible loop.
    Basically we run it until we have any other error than I/O error or it succeeds.
    We also set up a failsafe timer to prevent any unexpected infinite loop.
  */
  
  if (error === "CRYPT_E_FILE_ERROR" && outatime)
    throw new Failure("Couldn't verify trust information in time", "ETIMEDOUT");
    
  return result;
}

async function getCertificate(filePath){
  
  shouldStringNotEmpty(filePath);
  
  if (!allowed.includes(extname(filePath)))
    throw new Failure(`Accepted file types are: ${allowed.join(",")}`, 1);
  if (!await exists(filePath))
    throw new Failure("No such file", { code: "ENOENT", info: filePath });

  const failsafe = Date.now() + 1500; 
  let error, certificate, outatime;
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
        }], { optional: true }],
      }, new Failure("Unexpected result from the native addon !", {
        code: 0,
        info: { result, certificate }
      }));
      error = "ERROR_SUCCESS";
    }
  } while(
    error === "CRYPT_E_NO_MATCH" &&
    (outatime = Date.now() >= failsafe) === false
  )
  /*
    Because this Windows API is horrible to work with and fails many time I/O wise.
    To make it somehow reliable we have to do this horrible loop.
    Basically we run it until we have any other error than I/O error or it succeeds.
    We also set up a failsafe timer to prevent any unexpected infinite loop.
    
    Which for the sake of completeness could be triggered if this function is invoked without 
    having verified that the target is signed first with verifyTrust()
    (this case would be a legit "CRYPT_E_NO_MATCH" error).
  */
  
  if (error === "CRYPT_E_NO_MATCH" && outatime)
    throw new Failure("Couldn't get any certificate information in time", "ETIMEDOUT");
  
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