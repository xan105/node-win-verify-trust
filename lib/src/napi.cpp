/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

#include <napi.h>
#include "verifyTrust.h"
#include "certificate.h"

/* NAPI Initialize add-on*/
Napi::Object Init(Napi::Env env, Napi::Object exports){
  exports.Set("verifySignature", Napi::Function::New(env, verifySignature));
  exports.Set("certificateInfo", Napi::Function::New(env, certificateInfo));
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);