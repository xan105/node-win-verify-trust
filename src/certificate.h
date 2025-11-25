#include <napi.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <sstream>
#include <iomanip>
#include <atlconv.h>

#pragma comment(lib, "crypt32.lib")

typedef struct {
    LPWSTR lpszProgramName;
    LPWSTR lpszPublisherLink;
    LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, * PSPROG_PUBLISHERINFO;

BOOL getProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info);
BOOL getTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo);
Napi::Object getCertificateInformation(PCCERT_CONTEXT pCertContext, Napi::Env env);
Napi::Number certificateInfo(const Napi::CallbackInfo& info);