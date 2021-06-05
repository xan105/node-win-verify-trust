import { checkFileExt, exists } from './util.js';
import bindings from 'bindings';
const { verifySignature } = bindings('winVerifyTrust.node');

const isSigned = async function(filePath) {

  if (!await exists(filePath)) throw 'ENOENT : No such file (specified file does not exist)';
  if (!checkFileExt) throw 'ERR_UNEXPECTED_FILE_TYPE';
    
  const { code } = verifySignature(filePath);
  return ( code == 0 ) ? true : false;
}

const trustStatus = async function(filePath) {
  
  if (!await exists(filePath)) throw 'ENOENT : No such file (specified file does not exist)';
  if (!checkFileExt) throw 'ERR_UNEXPECTED_FILE_TYPE';
    
  const { message } = verifySignature(filePath);
  return message;
}

export { isSigned, trustStatus };
export default { isSigned, trustStatus };