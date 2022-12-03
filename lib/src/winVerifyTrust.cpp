/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.

Based from https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
Copyright (C) Microsoft. All rights reserved.
No copyright or trademark infringement is intended in using the aforementioned Microsoft example.
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
#pragma comment(lib, "crypt32.lib")

using namespace std;
#include <iostream>

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

typedef struct {
    LPWSTR lpszProgramName;
    LPWSTR lpszPublisherLink;
    LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, * PSPROG_PUBLISHERINFO;

BOOL getProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info);
Napi::Object getCertificateInformation(PCCERT_CONTEXT pCertContext, Napi::Env env);
BOOL getTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo);
std::wstring stringToWString(const std::string& s);
std::string wstringToString(std::wstring wstring);
LPWSTR allocateAndCopyWideString(LPCWSTR inputString);

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

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)

/* Authenticode */

BOOL getProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info){
    
    BOOL fReturn = FALSE;
    PSPC_SP_OPUS_INFO OpusInfo = NULL;
    DWORD dwData;
    BOOL fResult;

    // Loop through authenticated attributes and find
    // SPC_SP_OPUS_INFO_OBJID OID.
    for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
    {
       if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID,
            pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
       {
            // Get Size of SPC_SP_OPUS_INFO structure.
            fResult = CryptDecodeObject(ENCODING,
                SPC_SP_OPUS_INFO_OBJID,
                pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                0,
                NULL,
                &dwData);
            if (fResult)
            {
                // Allocate memory for SPC_SP_OPUS_INFO structure.
                OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
                if (OpusInfo)
                {
                    // Decode and get SPC_SP_OPUS_INFO structure.
                    fResult = CryptDecodeObject(ENCODING,
                        SPC_SP_OPUS_INFO_OBJID,
                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        OpusInfo,
                        &dwData);
                    if (fResult)
                    {
                        // Fill in Program Name if present.
                        if (OpusInfo->pwszProgramName)
                        {
                            Info->lpszProgramName =
                                allocateAndCopyWideString(OpusInfo->pwszProgramName);
                        }
                        else
                            Info->lpszProgramName = NULL;

                        // Fill in Publisher Information if present.
                        if (OpusInfo->pPublisherInfo)
                        {
                           switch (OpusInfo->pPublisherInfo->dwLinkChoice)
                           {
                                case SPC_URL_LINK_CHOICE:
                                    Info->lpszPublisherLink =
                                        allocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszUrl);
                                    break;

                                case SPC_FILE_LINK_CHOICE:
                                    Info->lpszPublisherLink =
                                        allocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszFile);
                                    break;

                                default:
                                    Info->lpszPublisherLink = NULL;
                                    break;
                                }
                        }
                        else
                        {
                           Info->lpszPublisherLink = NULL;
                        }

                        // Fill in More Info if present.
                        if (OpusInfo->pMoreInfo)
                        {
                            switch (OpusInfo->pMoreInfo->dwLinkChoice)
                            {
                                case SPC_URL_LINK_CHOICE:
                                    Info->lpszMoreInfoLink =
                                        allocateAndCopyWideString(OpusInfo->pMoreInfo->pwszUrl);
                                    break;

                                case SPC_FILE_LINK_CHOICE:
                                    Info->lpszMoreInfoLink =
                                        allocateAndCopyWideString(OpusInfo->pMoreInfo->pwszFile);
                                    break;

                                default:
                                    Info->lpszMoreInfoLink = NULL;
                                    break;
                                }
                        }
                        else
                        {
                            Info->lpszMoreInfoLink = NULL;
                        }

                        fReturn = TRUE;
                    }
                }
            }
            break; // Break from for loop.

       } // lstrcmp SPC_SP_OPUS_INFO_OBJID 
    } // for 
    
    //Clean up
    if (OpusInfo != NULL) LocalFree(OpusInfo);

    return fReturn;
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

BOOL getTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo)
{
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fReturn = FALSE;
    BOOL fResult;
    DWORD dwSize;

    *pCounterSignerInfo = NULL;

    // Loop through unathenticated attributes for
    // szOID_RSA_counterSign OID.
    for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
    {
        if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
                szOID_RSA_counterSign) == 0)
        {
            // Get size of CMSG_SIGNER_INFO structure.
            fResult = CryptDecodeObject(ENCODING,
                PKCS7_SIGNER_INFO,
                pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                0,
                NULL,
                &dwSize);
            if (fResult)
            {
                // Allocate memory for CMSG_SIGNER_INFO.
                *pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
                if (*pCounterSignerInfo)
                {
                    // Decode and get CMSG_SIGNER_INFO structure
                    // for timestamp certificate.
                    fResult = CryptDecodeObject(ENCODING,
                        PKCS7_SIGNER_INFO,
                        pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                        pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        (PVOID)*pCounterSignerInfo,
                        &dwSize);
                    if (fResult)
                    {
                        fReturn = TRUE;
                    }
                }
            }
            break; // Break from for loop.
        }
    }

    // Clean up.
    if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);

    return fReturn;
}

/* Util */

std::wstring stringToWString(const std::string& s)
{
    int length;
    int slength = (int)s.length() + 1;
    length = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    std::wstring buf;
    buf.resize(length);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, const_cast<wchar_t*>(buf.c_str()), length);
    return buf;
}

int size_tToInt(size_t val) { //64bits
    return (val <= INT_MAX) ? (int)((size_t)val) : 0;
}

std::string wstringToString(std::wstring wstring) {

    std::string result;

    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, &wstring[0], size_tToInt(wstring.size()), NULL, 0, NULL, NULL);
    result = std::string(size, 0);
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, &wstring[0], size_tToInt(wstring.size()), &result[0], size, NULL, NULL);

    return result;
}

LPWSTR allocateAndCopyWideString(LPCWSTR inputString)
{
    LPWSTR outputString = NULL;

    outputString = (LPWSTR)LocalAlloc(LPTR,
        (wcslen(inputString) + 1) * sizeof(WCHAR));
    if (outputString != NULL)
    {
        lstrcpyW(outputString, inputString);
    }
    return outputString;
}