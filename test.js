// @ts-check
/// <reference path="./index.d.ts" />
const fs = require("fs");
/**
 * @type {Pkcs11Js}
 */
const pkcs11 = require(".");

const json = fs.readFileSync("config.json", { encoding: "utf8" });
const config = JSON.parse(json);

var mod = new pkcs11.PKCS11();
mod.load(config.lib);

mod.C_Initialize();

function OpenSession() {
    const slotList = mod.C_GetSlotList();
    const session = mod.C_OpenSession(slotList[config.slot], pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION);
    mod.C_Login(session, 1, config.pin); // CKU_USER

    return session;
}

function GenerateTestKeyPair() {
    console.log("Generate RSA key pair (m: 1024, e: 65537)")
    const session = OpenSession();
    try {
        const key = mod.C_GenerateKeyPair(session,
            {
                mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN,
                parameter: null
            },
            [
                { type: pkcs11.CKA_TOKEN, value: true },
                { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
                { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
                { type: pkcs11.CKA_PRIVATE, value: false },
                { type: pkcs11.CKA_LABEL, value: new Buffer("test") },
                { type: pkcs11.CKA_ID, value: new Buffer("id_verify") },
                { type: pkcs11.CKA_VERIFY, value: true },
                { type: pkcs11.CKA_ENCRYPT, value: false },
                { type: pkcs11.CKA_WRAP, value: false },
                { type: pkcs11.CKA_MODULUS_BITS, value: 1024 << 3 },
                { type: pkcs11.CKA_PUBLIC_EXPONENT, value: new Buffer([1, 0, 1]) },
            ],
            [
                { type: pkcs11.CKA_TOKEN, value: true },
                { type: pkcs11.CKA_SENSITIVE, value: true },
                { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
                { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
                { type: pkcs11.CKA_PRIVATE, value: true },
                { type: pkcs11.CKA_LABEL, value: new Buffer("test") },
                { type: pkcs11.CKA_ID, value: new Buffer("id_sign") },
                { type: pkcs11.CKA_EXTRACTABLE, value: false },
                { type: pkcs11.CKA_DERIVE, value: false },
                { type: pkcs11.CKA_SIGN, value: true },
                { type: pkcs11.CKA_DECRYPT, value: false },
                { type: pkcs11.CKA_UNWRAP, value: false },
            ],
        )

    } catch (err) {
        console.error(err);
    }

    mod.C_CloseSession(session);
}

function RemoveTestKeyPair() {
    console.log("Remove test key pair");
    const session = OpenSession();
    mod.C_FindObjectsInit(session,
        [
            { type: pkcs11.CKA_LABEL, value: new Buffer("test") },
        ],
    );

    let obj;
    const destroyObjects = [];
    while (obj = mod.C_FindObjects(session)) {
        destroyObjects.push(obj);
    }

    mod.C_FindObjectsFinal(session);

    destroyObjects.forEach((item) => {
        mod.C_DestroyObject(session, item)
    })

    mod.C_CloseSession(session);
}

function TestSign(cb) {
    const sessions = Array(config.threads).fill(0)
        .map((thread) => {
            const session = OpenSession();

            // Find key
            mod.C_FindObjectsInit(
                session,
                [
                    { type: pkcs11.CKA_LABEL, value: new Buffer("test") },
                ],
            );
            let obj;
            let privateKey, publicKey;
            while (obj = mod.C_FindObjects(session)) {
                const cls = mod.C_GetAttributeValue(session, obj, [{ type: pkcs11.CKA_CLASS }])[0].value[0];
                if (cls === pkcs11.CKO_PRIVATE_KEY) {
                    privateKey = obj;
                } else if (cls === pkcs11.CKO_PUBLIC_KEY) {
                    publicKey = obj;
                }
            }
            mod.C_FindObjectsFinal(session);

            return {
                session,
                privateKey,
                publicKey,
            };
        });

    const data = new Buffer(config.buffer);

    let sesRefCount = 0;
    for (let i = 0; i < config.threads; i++) {
        (() => {
            sesRefCount++;
            const item = sessions[i];
            const signature = new Buffer(1024);

            let refCount = config.iterations;


            function test(cb2) {
                // setTimeout(() => {
                //     refCount--;
                //     if (!refCount) {
                //         cb2();
                //     } else {
                //         test(cb2);
                //     }
                // }, 10);
                mod.C_SignInit(item.session,
                    {
                        mechanism: pkcs11.CKM_SHA1_RSA_PKCS,
                        parameter: null,
                    },
                    item.privateKey,
                );

                mod.C_Sign(item.session, data, signature, (err, sig) => {
                    if (err) {
                        console.log(err)
                    }
                    refCount--;
                    if (!refCount) {
                        cb2();
                    } else {
                        test(cb2);
                    }
                });
            }

            test(() => {
                sesRefCount--;
                if (!sesRefCount) {

                    sessions.forEach((item) => {
                        mod.C_CloseSession(item.session);
                    });

                    cb();
                }
            });
        })();

    }

}

GenerateTestKeyPair();

console.time("Sign test");
TestSign(() => {
    RemoveTestKeyPair();
    console.timeEnd("Sign test");

    mod.C_CloseAllSessions(mod.C_GetSlotList()[config.slot]);
    mod.C_Finalize();
    console.log("success")
});
