import { parse } from 'node:path';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';

function checkFileExt(filePath) {
  const allowed = [ '.exe', '.cab', '.dll', '.ocx', '.msi', '.xpi' ];
  const ext = parse(filePath).ext;
  return allowed.includes(ext) ? true : false
}

function exists(target) {
   return new Promise((resolve) => {
      access(target, constants.F_OK).then(() => resolve(true)).catch(() => resolve(false));
   });
}

export { checkFileExt, exists };