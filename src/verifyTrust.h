#include <napi.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#pragma comment (lib, "wintrust")

Napi::Number verifySignature(const Napi::CallbackInfo& info);