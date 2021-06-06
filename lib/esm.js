/*
MIT License

Copyright (c) 2021 Anthony Beaumont

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import { checkFileExt, exists } from './util.js';
import bindings from 'bindings';
const { verifySignature } = bindings('winVerifyTrust.node');

const isSignedVerbose = async function(filePath) {
  
  if (!await exists(filePath)) throw 'ERR_NO_SUCH_FILE';
  if (!checkFileExt(filePath)) throw 'ERR_UNEXPECTED_FILE_TYPE';
    
  return verifySignature(filePath);
}

const isSigned = async function(filePath) {
  const { signed } = await isSignedVerbose(filePath);
  return signed;
}

const trustStatus = async function(filePath) {
  const { message } = await isSignedVerbose(filePath);
  return message;
}

export { isSigned, trustStatus, isSignedVerbose };