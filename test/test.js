import { isSigned, verifyTrust, getCertificate } from "../lib/index.js";
import t from "tap";

const sample = {
  signed: "./test/sample/signed.dll",
  unsigned: "./test/sample/unsigned.dll",
  enoent: "./test/sample/idontexist.dll",
  ext: "./test/sample/empty.txt"
};

t.test('isSigned()', async t => {

  await t.test('test file is signed', async t => t.strictSame(await isSigned(sample.signed, "valve"), true));
  await t.test('test file is not signed', async t => t.strictSame(await isSigned(sample.unsigned), false));
  await t.test('test file does not exist', async t => t.strictSame(await isSigned(sample.enoent), false));
  await t.test('test disallowed file ext', async t => t.strictSame(await isSigned(sample.ext), false));
  t.end();
  
});

t.test('verifyTrust()', async t => {
  await t.test('test file does not exist', async t => t.rejects(verifyTrust(sample.enoent), "ENOENT"));
  await t.test('test disallowed file ext', async t => t.rejects(verifyTrust(sample.ext), "ERR_UNEXPECTED"));
  t.end();
});

t.test('getCertificate()', async t => {
  await t.test('test file does not exist', async t => t.rejects(getCertificate(sample.enoent), "ENOENT"));
  await t.test('test disallowed file ext', async t => t.rejects(getCertificate(sample.ext), "ERR_UNEXPECTED"));
  t.end();
});