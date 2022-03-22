import { isSigned, trustStatus } from "../lib/index.js";
import { resolve } from "node:path";
import t from "tap";

const sample = {
  signed: resolve("./test/sample/signed.dll"),
  unsigned: resolve("./test/sample/unsigned.dll"),
  enoent: resolve("./test/sample/idontexist.dll"),
  ext: resolve("./test/sample/empty.txt")
};

t.test('isSigned()', async t => {

  await t.test('test file is signed', async t => t.strictSame(await isSigned(sample.signed), true));
  await t.test('test file is not signed', async t => t.strictSame(await isSigned(sample.unsigned), false));
  await t.test('test file does not exist', async t => t.rejects(isSigned(sample.enoent), "ERR_NO_SUCH_FILE"));
  await t.test('test disallowed file ext', async t => t.rejects(isSigned(sample.ext), "ERR_UNEXPECTED_FILE_TYPE"));
  t.end();
  
});

t.test('trustStatus()', async t => {

  await t.test('test file is signed', async t => t.strictSame(await trustStatus(sample.signed), "The file is signed and the signature was verified"));
  await t.test('test file is not signed', async t => t.strictSame(await trustStatus(sample.unsigned), "The file is not signed"));
  await t.test('test file does not exist', async t => t.rejects(trustStatus(sample.enoent), "ERR_NO_SUCH_FILE"));
  await t.test('test disallowed file ext', async t => t.rejects(trustStatus(sample.ext), "ERR_UNEXPECTED_FILE_TYPE"));
  t.end();
  
});