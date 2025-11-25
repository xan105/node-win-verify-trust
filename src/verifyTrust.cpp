/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.

Based from https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
Copyright (C) Microsoft. All rights reserved.
No copyright or trademark infringement is intended in using the aforementioned Microsoft example.
*/

#define _UNICODE 1
#define UNICODE 1

#include "verifyTrust.h"
#include "string.h"

Napi::Number verifySignature(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  
  unsigned int length = info.Length();
  if (length != 1) Napi::TypeError::New(env, "Expected 1 argument").ThrowAsJavaScriptException();
  
  if (!info[0].IsString()) Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
  Napi::String filePath = info[0].As<Napi::String>();
  LPCWSTR pwszSourceFile = stringToWString(filePath).c_str();
  
  Napi::Number result;
  LONG lStatus;

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
  
  if (lStatus == TRUST_E_NOSIGNATURE) { // Get the reason for no signature.
    result = Napi::Number::New(env, GetLastError());
  }
  else {
    result = Napi::Number::New(env, lStatus);
  }
  
  // Any hWVTStateData must be released by a call with close.
  WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

  lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
	
  return result;
}