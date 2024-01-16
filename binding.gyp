{
  "targets": [
    {
      "target_name": "pkcs11",
      "sources": [
        "src/dl.cpp",
        "src/common.cpp",
        "src/main.cpp" ,
      ],
      "include_dirs": [
        "includes",
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
      ],
      'conditions': [
        ['OS=="win"', {
          'msvs_settings': {
            'VCCLCompilerTool': {
              'AdditionalOptions': [ '-std:c++17' ],
            },
          },
        }],
      ],
    }
  ]
}