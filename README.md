About
=====

Check the signature of a file using the WinVerifyTrust API.

Example
=======

Dead simple:

```js
import { isSigned } from "@xan105/win-verify-trust";
const trusted = await isSigned("/path/to/file");
console.log(trusted) //boolean
```

Verbose:

```js
import { verifyTrust } from "@xan105/win-verify-trust";
const { trusted, message } = await verifyTrust("/path/to/file");
console.log(trusted, message) 
//true
//"The file is signed and the signature was verified"
```

Installation
============

```
npm install @xan105/win-verify-trust
```

Force compiling:
```
npm install @xan105/win-verify-trust --build-from-source
```

You will need C/C++ build tools and Python 3.x (node-gyp) to build this module.<br />

API
===

⚠️ This module is only available as an ECMAScript module (ESM).

## Named export

#### `verifyTrust(filePath: string): Promise<object>`

Performs a trust verification action on the specified file using the WinVerifyTrust API.

**Return value**

Returns an object as

```ts
{
  trusted: boolean,
  message: string
}
``

Where `trusted` indicates if the file is signed and the signature was verified.<br/>
And `message` the details of the trust status (verbose).

_eg: "No signature was present in the subject"_

**Remarks**

❌ This function will throw if the target file doesn't exist or file ext isn't allowed.<br/>
⚠️ Allowed ext are: ".exe", ".cab", ".dll", ".ocx", ".msi", ".msix", ".xpi", ".ps1".

#### `isSigned(filePath: string): Promise<boolean>`

Check if the specified file is signed and trusted.<br />
This is a shorthand of `verifyTrust()`.<br />
This function doesn't throw.