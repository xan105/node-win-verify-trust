About
=====

Check the signature of a file using the WinVerifyTrust API.<br />
Retrieve some certificate information.

📦 Scoped `@xan105` packages are for my own personal use but feel free to use them.

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

Once you know a file is signed and the signature was verified.<br/>
You may want to check some info of the cert:

```js
import { getCertificate } from "@xan105/win-verify-trust";

const certificate = await getCertificate("steam_api64.dll");
console.log(certificate) 
/*
{
  signer: {
    issuer: 'DigiCert SHA2 Assured ID Code Signing CA',
    subject: 'Valve'
  },
  timestamp: {
    issuer: 'Symantec Time Stamping Services CA - G2',
    subject: 'Symantec Time Stamping Services Signer - G4'
  }
}
*/
```

💡 You can pass an optional arg to `isSigned()` <br/>
to also check that the cert was signed for the specified subject:

```js
import { isSigned } from "@xan105/win-verify-trust";

const trusted = await isSigned("steam_api64.dll", "valve");
console.log(trusted) //boolean
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
🚀 x64 prebuilt binary provided.

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
```

Where `trusted` indicates if the file is signed and the signature was verified.<br/>
And `message` the details of the trust status (verbose).

_eg: "No signature was present in the subject"_

**Remarks**

❌ This function will throw if the target file doesn't exist or file ext isn't allowed.<br/>
⚠️ Allowed ext are: ".exe", ".cab", ".dll", ".ocx", ".msi", ".msix", ".xpi", ".ps1".

#### `getCertificate(filePath: string): Promise<object>`

Retrieve some certificate information.<br/>
Once you know a file is signed and the signature was verified after having used `verifyTrust()`  you may want to check some certificate information. 

**Return value**

Returns an object as

```ts
{
  programName?: string,
  publisherLink?: string,
  infoLink?: string,
  signer: {
    issuer?: string,
    subject?: string
  },
  timestamp: {
    issuer?: string,
    subject?: string
  }
}
```

Where `signer` contains information from the _signer certificate_ and `timestamp` from the _timestamp certificate_.

`programName` is the program name, `publisherLink` and `infoLink` are publisher information.

**Remarks**

❌ This function will throw on error.<br/>
⚠️ Allowed ext are: ".exe", ".cab", ".dll", ".ocx", ".msi", ".msix", ".xpi", ".ps1".

#### `isSigned(filePath: string, name?: string | null): Promise<boolean>`

Check if the specified file is signed and trusted.<br />
Optionally also check that the signer certificate was issued for the specified subject name (_case-insensitive_).

This is a shorthand of `verifyTrust()` and `getCertificate()`.<br />
This function doesn't throw.