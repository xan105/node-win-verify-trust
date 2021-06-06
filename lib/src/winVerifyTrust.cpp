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

#include <napi.h>

#define _UNICODE 1
#define UNICODE 1

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#pragma comment (lib, "wintrust")

using namespace std;
#include <iostream>

std::wstring stringToWString(const std::string &s)
{
    int length;
    int slength = (int)s.length() + 1;
    length = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    std::wstring buf;
    buf.resize(length);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, const_cast<wchar_t *>(buf.c_str()), length);
    return buf;
}

Napi::Object verifySignature(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  
  int length = info.Length();
  if (length != 1 || !info[0].IsString()) Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
  Napi::String filePath = info[0].As<Napi::String>();
  
  Napi::Object result = Napi::Object::New(env);

  std::wstring wrapper = stringToWString(filePath);
  LPCWSTR pwszSourceFile = wrapper.c_str();
  
  /* 
  From https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
  Copyright (C) Microsoft. All rights reserved.
  No copyright or trademark infringement is intended in using the aforementioned Microsoft example.
  */
  
  LONG lStatus;
  DWORD dwLastError;

  // Initialize the WINTRUST_FILE_INFO structure.

  WINTRUST_FILE_INFO FileData;
  memset(&FileData, 0, sizeof(FileData));
  FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
  FileData.pcwszFilePath = pwszSourceFile;
  FileData.hFile = NULL;
  FileData.pgKnownSubject = NULL;
  
  GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA WinTrustData;

  // Initialize the WinVerifyTrust input data structure.

  // Default all fields to 0.
  memset(&WinTrustData, 0, sizeof(WinTrustData));

  WinTrustData.cbStruct = sizeof(WinTrustData);
    
  // Use default code signing EKU.
  WinTrustData.pPolicyCallbackData = NULL;

  // No data to pass to SIP.
  WinTrustData.pSIPClientData = NULL;

  // Disable WVT UI.
  WinTrustData.dwUIChoice = WTD_UI_NONE;

  // No revocation checking.
  WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 

  // Verify an embedded signature on a file.
  WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

  // Verify action.
  WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

  // Verification sets this value.
  WinTrustData.hWVTStateData = NULL;

  // Not used.
  WinTrustData.pwszURLReference = NULL;

  // This is not applicable if there is no UI because it changes 
  // the UI to accommodate running applications instead of 
  // installing applications.
  WinTrustData.dwUIContext = 0;

  // Set pFile.
  WinTrustData.pFile = &FileData;

  // WinVerifyTrust verifies signatures as specified by the GUID 
  // and Wintrust_Data.
  lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
  
  switch (lStatus) 
  {
    case ERROR_SUCCESS:
      result.Set("signed", true);
      result.Set("message", "The file is signed and the signature was verified");
      break;
        
    case TRUST_E_NOSIGNATURE:
      // The file was not signed or had a signature that was not valid.
      // Get the reason for no signature.
      dwLastError = GetLastError();
      if (TRUST_E_NOSIGNATURE == dwLastError ||
          TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
          TRUST_E_PROVIDER_UNKNOWN == dwLastError) 
      {
        result.Set("signed", false);
        result.Set("message", "The file is not signed");     
      } 
      else 
      {
        result.Set("signed", false);
        result.Set("message", "An unknown error occurred trying to verify the signature of the file");
      }
      break;

    case TRUST_E_EXPLICIT_DISTRUST:
      result.Set("signed", false);
      result.Set("message", "The signature is present but specifically disallowed by the admin or user");     
      break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
      result.Set("signed", false);
      result.Set("message", "The signature is present but not trusted"); 
      break;

    case CRYPT_E_SECURITY_SETTINGS:
      result.Set("signed", false);
      result.Set("message", "The signature wasn't explicitly trusted by the admin and admin policy has disabled user trust. No signature, publisher or timestamp errors"); 
      break;

    default:
      result.Set("signed", false);
      result.Set("message", "The UI was disabled in dwUIChoice or the admin policy has disabled user trust");
      break;
  }

  // Any hWVTStateData must be released by a call with close.
  WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

  lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
	
	return result;
}

/* NAPI Initialize add-on*/

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  
  exports.Set("verifySignature", Napi::Function::New(env, verifySignature));
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)