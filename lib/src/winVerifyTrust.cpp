/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.

Based from https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
and https://learn.microsoft.com/en-us/troubleshoot/windows/win32/get-information-authenticode-signed-executables
Copyright (C) Microsoft. All rights reserved.
No copyright or trademark infringement is intended in using the aforementioned Microsoft example.
*/

#define _UNICODE 1
#define UNICODE 1

#include <napi.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#pragma comment (lib, "wintrust")
#pragma comment(lib, "crypt32.lib")

using namespace std;
#include <iostream>

#include "string.h"
#include "certificate.h"

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

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

Napi::Object getCertificateInformation(PCCERT_CONTEXT pCertContext, Napi::Env env) {

    Napi::Object certificate = Napi::Object::New(env);

    // Get signer certificate information
    DWORD dwData;
    LPTSTR szName = NULL;
    // Get Issuer name size.
    if ((dwData = CertGetNameString(pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_ISSUER_FLAG,
        NULL,
        NULL,
        0)))
    {
        // Allocate memory for Issuer name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (szName)
        {
            // Get Issuer name.
            if ((CertGetNameString(pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG,
                NULL,
                szName,
                dwData)))
            {
                certificate.Set("issuer", wstringToString(szName).c_str());
            }
        }
        LocalFree(szName);
        szName = NULL;
    }

    // Get Subject name size.
    if ((dwData = CertGetNameString(pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        NULL,
        0)))
    {
        // Allocate memory for subject name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (szName)
        {
            // Get subject name.
            if ((CertGetNameString(pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                NULL,
                szName,
                dwData)))
            {
                certificate.Set("subject", wstringToString(szName).c_str());
            }
        }
        LocalFree(szName);
        szName = NULL;
    }
    return certificate;
}

Napi::Number certificateInfo(const Napi::CallbackInfo& info){
    Napi::Env env = info.Env();

    unsigned int length = info.Length();
    if (length != 2) Napi::TypeError::New(env, "Expected 2 argument").ThrowAsJavaScriptException();

    if (!info[0].IsString()) Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
    Napi::String filePath = info[0].As<Napi::String>();
    LPCWSTR szFileName = stringToWString(filePath).c_str();

    if (!info[1].IsObject()) Napi::TypeError::New(env, "Object expected").ThrowAsJavaScriptException();
    Napi::Object certificate = info[1].As<Napi::Object>();

    Napi::Number result = Napi::Number::New(env, 0);

    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fResult;
    DWORD dwEncoding, dwContentType, dwFormatType;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
    SPROG_PUBLISHERINFO ProgPubInfo;
    DWORD dwSignerInfo;
    CERT_INFO CertInfo;

    ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));
    // Get message handle and store handle from the signed file.
    fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
            szFileName,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &dwEncoding,
            &dwContentType,
            &dwFormatType,
            &hStore,
            &hMsg,
            NULL);
    if (!fResult) result = Napi::Number::New(env, GetLastError());
    else {
        // Get signer information size.
        fResult = CryptMsgGetParam(hMsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            NULL,
            &dwSignerInfo);
        if (!fResult) result = Napi::Number::New(env, GetLastError());
        else {
            // Allocate memory for signer information.
            pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
            if (!pSignerInfo) result = Napi::Number::New(env, GetLastError());
            else {
                // Get Signer Information.
                fResult = CryptMsgGetParam(hMsg,
                    CMSG_SIGNER_INFO_PARAM,
                    0,
                    (PVOID)pSignerInfo,
                    &dwSignerInfo);
                if (!fResult) result = Napi::Number::New(env, GetLastError());
                else 
                {
                    // Get program name and publisher information from 
                    // signer info structure.
                    if (getProgAndPublisherInfo(pSignerInfo, &ProgPubInfo))
                    {
                        if (ProgPubInfo.lpszProgramName != NULL)
                            certificate.Set("programName", wstringToString(ProgPubInfo.lpszProgramName).c_str());
                        if (ProgPubInfo.lpszPublisherLink != NULL)
                            certificate.Set("publisherLink", wstringToString(ProgPubInfo.lpszPublisherLink).c_str());
                        if (ProgPubInfo.lpszMoreInfoLink != NULL)
                            certificate.Set("infoLink", wstringToString(ProgPubInfo.lpszMoreInfoLink).c_str());
                    }
                    // Search for the signer certificate in the temporary 
                    // certificate store.
                    CertInfo.Issuer = pSignerInfo->Issuer;
                    CertInfo.SerialNumber = pSignerInfo->SerialNumber;
                    pCertContext = CertFindCertificateInStore(hStore,
                        ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        (PVOID)&CertInfo,
                        NULL);
                    if (!pCertContext) result = Napi::Number::New(env, GetLastError());
                    else 
                    {
                        //Get signer certificate information
                        certificate.Set("signer", getCertificateInformation(pCertContext, env));
                        
                        // Get the timestamp certificate signerinfo structure.
                        // szOID_RSA_counterSign (legacy signature standard)
                        // szOID_RFC3161_counterSign is not implemented
                        if (getTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo))
                        {
                            // Search for Timestamp certificate in the temporary
                            // certificate store.
                            CertInfo.Issuer = pCounterSignerInfo->Issuer;
                            CertInfo.SerialNumber = pCounterSignerInfo->SerialNumber;

                            pCertContext = CertFindCertificateInStore(hStore,
                                ENCODING,
                                0,
                                CERT_FIND_SUBJECT_CERT,
                                (PVOID)&CertInfo,
                                NULL);
                            if (pCertContext)
                            {
                                // Get timestamp certificate information.
                                certificate.Set("timestamp", getCertificateInformation(pCertContext, env));
                            }
                        }
                    }
                }
            }
        }
    }

    // Clean up.
    if (ProgPubInfo.lpszProgramName != NULL)
         LocalFree(ProgPubInfo.lpszProgramName);
    if (ProgPubInfo.lpszPublisherLink != NULL)
         LocalFree(ProgPubInfo.lpszPublisherLink);
    if (ProgPubInfo.lpszMoreInfoLink != NULL)
         LocalFree(ProgPubInfo.lpszMoreInfoLink);
    if (pSignerInfo != NULL) 
         LocalFree(pSignerInfo);
    if (pCounterSignerInfo != NULL) 
         LocalFree(pCounterSignerInfo);
    if (pCertContext != NULL) 
         CertFreeCertificateContext(pCertContext);
    if (hStore != NULL) 
         CertCloseStore(hStore, 0);
    if (hMsg != NULL) 
         CryptMsgClose(hMsg);

    return result;
}

/* NAPI Initialize add-on*/

Napi::Object Init(Napi::Env env, Napi::Object exports){
  
  exports.Set("verifySignature", Napi::Function::New(env, verifySignature));
  exports.Set("certificateInfo", Napi::Function::New(env, certificateInfo));
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);