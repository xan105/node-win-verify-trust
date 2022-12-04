{
    "targets": [{
        "target_name": "winVerifyTrust",
        "cflags!": [ "-fno-exceptions" ],
        "cflags_cc!": [ "-fno-exceptions" ],
        "sources": [
            "lib/src/winVerifyTrust.cpp",
            "lib/src/certificate.cpp",
            "lib/src/string.cpp"
        ],
        "msvs_settings": {
          "VCCLCompilerTool": {
             "ExceptionHandling": 1,
             "AdditionalOptions": []
          }
         },
        'include_dirs': [
            "<!@(node -p \"require('node-addon-api').include\")"
        ],
        'libraries': [],
        'dependencies': [
            "<!(node -p \"require('node-addon-api').gyp\")"
        ],
        'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
    }]
}