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

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#pragma comment (lib, "wintrust")
#pragma comment(lib, "crypt32.lib")

#include "string.h"
#include "certificate.h"

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

BOOL getProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info) {

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

BOOL getTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo)
{
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fReturn = FALSE;
    BOOL fResult;
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