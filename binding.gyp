{
    "variables": {
    },
    "targets": [
        {
            "include_dirs": [
                "<!(node -e \"require(\'nan\')\")",
                "includes"
            ],
            "target_name": "pkcs11",
            "sources": [
                 "src/main.cpp",
                 "src/dl.cpp",
                 "src/const.cpp",
                 "src/pkcs11.cpp"
            ],
            'conditions': [
                ['OS=="mac"', {
                'xcode_settings': {
                    'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
                    'MACOSX_DEPLOYMENT_TARGET': '10.5',
                    'OTHER_CFLAGS': [
                        '-ObjC++'
                    ]
                },
                'libraries': [
                    '-lobjc'
                ],
                }]
            ]
        }
    ]
}