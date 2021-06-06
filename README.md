Check the signature of an executable file using the WinVerifyTrust API.

Example
=======

```js

import { isSigned, trustStatus } from "@xan105/win-verify-trust";

console.log( await isSigned("path/to/file") ); //True (Signed) or False

console.log( await trustStatus("path/to/file") ); //Verbose
/* Example: 
  "The signature is present but not trusted"
*/
```

Installation
============

`npm install @xan105/win-verify-trust`

You will need C/C++ build tools and Python 3.x (node-gyp) to build this module.

API
===

⚠️ This module is only available as an ECMAScript module (ESM) with named export.

Only the following file ext are allowed : '.exe', '.cab', '.dll', '.ocx', '.msi', '.msix', '.xpi'

### <Promise> isSigned(string filePath) : bool

Check if specified filePath is signed.

Return true (signed), false (unsigned).

### <Promise> trustStatus(string filePath) : string

Return the trust status (verbose) of the specified filePath:

- The file is signed and the signature was verified
- The file is not signed
- An unknown error occurred trying to verify the signature of the file
- The signature is present but specifically disallowed by the admin or user
- The signature is present but not trusted
- The signature wasn't explicitly trusted by the admin and admin policy has disabled user trust. No signature, publisher or timestamp errors
- The UI was disabled in dwUIChoice or the admin policy has disabled user trust

### <Promise> isSignedVerbose(string filePath) : <obj>{bool signed, string message}

If you need the result of both in one go. 