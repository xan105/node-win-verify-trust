import { isSigned, trustStatus } from "../lib/esm.js";

const sample = {
  signed: "./sample/signed.dll",
  unsigned: "./sample/unsigned.dll"
};

(async()=>{

  console.log("Signed is " + await isSigned(sample.signed) + " (" + await trustStatus(sample.signed) + ")");
  console.log("Un-signed is " + await isSigned(sample.unsigned) + " (" + await trustStatus(sample.unsigned) + ")");

})().catch(console.error);