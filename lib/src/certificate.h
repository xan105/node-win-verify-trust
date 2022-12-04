#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#pragma comment (lib, "wintrust")
#pragma comment(lib, "crypt32.lib")

typedef struct {
    LPWSTR lpszProgramName;
    LPWSTR lpszPublisherLink;
    LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, * PSPROG_PUBLISHERINFO;

BOOL getProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info);
BOOL getTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo);