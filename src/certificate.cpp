/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.

Based from https://learn.microsoft.com/en-us/troubleshoot/windows/win32/get-information-authenticode-signed-executables
Copyright (C) Microsoft. All rights reserved.
No copyright or trademark infringement is intended in using the aforementioned Microsoft example.
*/

#define _UNICODE 1
#define UNICODE 1
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#include "certificate.h"
#include "string.h"

BOOL getProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info) {

    BOOL result = FALSE;
    PSPC_SP_OPUS_INFO OpusInfo = NULL;
    DWORD dwData;

    // Loop through authenticated attributes and find
    // SPC_SP_OPUS_INFO_OBJID OID.
    for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
    {
        if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID,
            pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
        {
            // Get Size of SPC_SP_OPUS_INFO structure.
            if(CryptDecodeObject(ENCODING,
                SPC_SP_OPUS_INFO_OBJID,
                pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                0,
                NULL,
                &dwData))
            {
                // Allocate memory for SPC_SP_OPUS_INFO structure.
                OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
                if (OpusInfo)
                {
                    // Decode and get SPC_SP_OPUS_INFO structure.
                    if(CryptDecodeObject(ENCODING,
                        SPC_SP_OPUS_INFO_OBJID,
                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        OpusInfo,
                        &dwData))
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

                        result = TRUE;
                    }
                }
            }
            break; // Break from for loop.

        } // lstrcmp SPC_SP_OPUS_INFO_OBJID 
    } // for 

    //Clean up
    if (OpusInfo != NULL) LocalFree(OpusInfo);

    return result;
}

BOOL getTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo)
{
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL result = FALSE;
    DWORD dwSize;

    *pCounterSignerInfo = NULL;

    // Loop through unathenticated attributes for
    for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
    {
        // szOID_RSA_counterSign (legacy signature standard)
        if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
            szOID_RSA_counterSign) == 0)
        {
            // Get size of CMSG_SIGNER_INFO structure.
            if(CryptDecodeObject(ENCODING,
                PKCS7_SIGNER_INFO,
                pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                0,
                NULL,
                &dwSize))
            {
                // Allocate memory for CMSG_SIGNER_INFO.
                *pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
                if (*pCounterSignerInfo)
                {
                    // Decode and get CMSG_SIGNER_INFO structure
                    // for timestamp certificate.
                    if(CryptDecodeObject(ENCODING,
                        PKCS7_SIGNER_INFO,
                        pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                        pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                        0,
                        (PVOID)*pCounterSignerInfo,
                        &dwSize))
                    {
                        result = TRUE;
                    }
                }
            }
            break; // Break from for loop.
        }
        // szOID_RFC3161_counterSign
        /*
        else if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
                 szOID_RFC3161_counterSign) == 0)
        {
        }
        */
    }

    // Clean up.
    if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);

    return result;
}

Napi::Object getCertificateInformation(PCCERT_CONTEXT pCertContext, CRYPT_ALGORITHM_IDENTIFIER* pHashAlgo, Napi::Env env) {

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

    // Get Serial Number.
    std::ostringstream stringStream;
    dwData = pCertContext->pCertInfo->SerialNumber.cbData;
    for (DWORD n = 0; n < dwData; n++)
    {
        stringStream << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)];
    }
    std::string serialNumber = stringStream.str();
    certificate.Set("serialNumber", serialNumber.c_str());

    // Digest algorithm.
    if (pHashAlgo && pHashAlgo->pszObjId)
    {
        PCCRYPT_OID_INFO pCOI = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pHashAlgo->pszObjId, 0);
        if (pCOI && pCOI->pwszName)
        {
            certificate.Set("digestAlgo", wstringToString(pCOI->pwszName).c_str());
        }
        else
        {
            USES_CONVERSION;
            certificate.Set("digestAlgo", wstringToString(A2W(pHashAlgo->pszObjId)).c_str());
        }
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
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
    SPROG_PUBLISHERINFO ProgPubInfo;
    DWORD dwSignerInfo;
    CERT_INFO CertInfo;

    ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));
    // Get message handle and store handle from the signed file.
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
        szFileName,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        NULL,
        NULL,
        NULL,
        &hStore,
        &hMsg,
        NULL)) 
    {
        // Get signer information size.
        if (CryptMsgGetParam(hMsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            NULL,
            &dwSignerInfo)) 
        {
            // Allocate memory for signer information.
            if ((pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo)))
            {
                // Get Signer Information.
                if (CryptMsgGetParam(hMsg,
                    CMSG_SIGNER_INFO_PARAM,
                    0,
                    (PVOID)pSignerInfo,
                    &dwSignerInfo))
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
                    if (pCertContext = CertFindCertificateInStore(hStore,
                        ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        (PVOID)&CertInfo,
                        NULL))
                    {
                        //Get signer certificate information
                        certificate.Set("signer", getCertificateInformation(pCertContext, &pSignerInfo->HashAlgorithm, env));

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
                                certificate.Set("timestamp", getCertificateInformation(pCertContext, &pCounterSignerInfo->HashAlgorithm, env));
                            }
                        }

                        //szOID_NESTED_SIGNATURE
                        // aka "dual sign" (eg: Putty.exe) 
                        //not implemented

                    }
                    else result = Napi::Number::New(env, GetLastError());
                }
                else result = Napi::Number::New(env, GetLastError());
            }
            else result = Napi::Number::New(env, GetLastError());
        }
        else result = Napi::Number::New(env, GetLastError());
    }
    else result = Napi::Number::New(env, GetLastError());

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