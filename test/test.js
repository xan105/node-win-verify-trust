import test from "node:test";
import assert from "node:assert/strict";
import { attemptify } from "@xan105/error";
import { isSigned, verifyTrust, getCertificate } from "../lib/index.js";

const sample = {
  signed: "./test/sample/signed.dll",
  selfsigned: "./test/sample/selfsigned.dll",
  unsigned: "./test/sample/unsigned.dll",
  enoent: "./test/sample/idontexist.dll",
  ext: "./test/sample/empty.txt"
};

test("isSigned()", async() => {
  await test(" file is signed", async() => {
    const result = await isSigned(sample.signed, "valve");
    assert.equal(result, true);
  });
  
  await test(" file is self-signed", async() => {
    const result = await isSigned(sample.selfsigned);
    assert.equal(result, false);
  });
  
  await test(" file is not signed", async() => {
    const result = await isSigned(sample.unsigned);
    assert.equal(result, false);
  });
  
  await test(" file does not exist", async() => {
    const result = await isSigned(sample.enoent);
    assert.equal(result, false);
  });
  
  await test(" disallowed file ext", async() => {
    const result = await isSigned(sample.ext);
    assert.equal(result, false);
  });
});

test("verifyTrust()", async() => {
  await test(" file does not exist", async() => {
    const [, err] = await attemptify(verifyTrust)(sample.enoent);
    assert.equal(err.code, "ENOENT");
  });
  
  await test(" disallowed file ext", async() => {
    const [, err] = await attemptify(verifyTrust)(sample.ext);
    assert.equal(err.code, "ERR_INVALID_ARG");
  });
});

test("getCertificate()", async() => {
  await test(" file does not exist", async() => {
    const [, err] = await attemptify(getCertificate)(sample.enoent);
    assert.equal(err.code, "ENOENT");
  });
  
  await test(" disallowed file ext", async() => {
    const [, err] = await attemptify(getCertificate)(sample.ext);
    assert.equal(err.code, "ERR_INVALID_ARG");
  });
  
  await test(" misusage", async() => {
    const [, err] = await attemptify(getCertificate)(sample.unsigned);
    assert.equal(err.code, "ETIMEDOUT");
  });
});