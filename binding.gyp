{
    "targets": [{
        "target_name": "winVerifyTrust",
        "cflags!": [ "-fno-exceptions" ],
        "cflags_cc!": [ "-fno-exceptions" ],
        "sources": [
            "lib/src/napi.cpp",
            "lib/src/verifyTrust.cpp",
            "lib/src/certificate.cpp",
            "lib/src/string.cpp"
        ],
        "msvs_settings": {
          "VCCLCompilerTool": {
             "ExceptionHandling": 1,
             "AdditionalOptions": []
          }
         },
        "include_dirs": [
            "<!(node -p \"require('node-addon-api').include_dir\")"
        ],
        "dependencies": [
            "<!(node -p \"require('node-addon-api').targets\"):node_addon_api_maybe"
        ],
        "defines": [ "NODE_ADDON_API_DISABLE_DEPRECATED" ]
    }]
}