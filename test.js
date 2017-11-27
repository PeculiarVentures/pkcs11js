// @ts-check
/// <reference path="./index.d.ts" />
var fs = require("fs");
/**
 * @type {Pkcs11Js}
 */
var pkcs11 = require(".");
var json = fs.readFileSync("config.json", { encoding: "utf8" });
var config = JSON.parse(json);
var mod = new pkcs11.PKCS11();
mod.load(config.lib);
mod.C_Initialize();
function OpenSession() {
    var slotList = mod.C_GetSlotList();
    // tslint:disable-next-line:no-bitwise
    var session = mod.C_OpenSession(slotList[config.slot], pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION);
    mod.C_Login(session, 1, config.pin); // CKU_USER
    return session;
}
function GenerateTestKeyPair() {
    console.log("Generate RSA key pair (m: 1024, e: 65537)");
    var session = OpenSession();
    try {
        var key = mod.C_GenerateKeyPair(session, {
            mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN,
            parameter: null
        }, [
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
        ], [
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
        ]);
    }
    catch (err) {
        console.error(err);
    }
    mod.C_CloseSession(session);
}
function RemoveTestKeyPair() {
    console.log("Remove test key pair");
    var session = OpenSession();
    mod.C_FindObjectsInit(session, [
        { type: pkcs11.CKA_LABEL, value: new Buffer("test") },
    ]);
    var obj;
    var destroyObjects = [];
    while (obj = mod.C_FindObjects(session)) {
        destroyObjects.push(obj);
    }
    mod.C_FindObjectsFinal(session);
    destroyObjects.forEach(function (item) {
        mod.C_DestroyObject(session, item);
    });
    mod.C_CloseSession(session);
}
function TestSign(cb) {
    var sessions = Array(config.threads).fill(0)
        .map(function (thread) {
        var session = OpenSession();
        // Find key
        mod.C_FindObjectsInit(session, [
            { type: pkcs11.CKA_LABEL, value: new Buffer("test") },
        ]);
        var obj;
        var privateKey, publicKey;
        while (obj = mod.C_FindObjects(session)) {
            var cls = mod.C_GetAttributeValue(session, obj, [{ type: pkcs11.CKA_CLASS }])[0].value[0];
            if (cls === pkcs11.CKO_PRIVATE_KEY) {
                privateKey = obj;
            }
            else if (cls === pkcs11.CKO_PUBLIC_KEY) {
                publicKey = obj;
            }
        }
        mod.C_FindObjectsFinal(session);
        return {
            session: session,
            privateKey: privateKey,
            publicKey: publicKey
        };
    });
    var data = new Buffer(config.buffer);
    var sesRefCount = 0;
    var sTime = Date.now();
    var _loop_1 = function (i) {
        (function () {
            sesRefCount++;
            var item = sessions[i];
            var signature = new Buffer(1024);
            var refCount = config.iterations;
            function test(cb2) {
                // setTimeout(() => {
                //     refCount--;
                //     if (!refCount) {
                //         cb2();
                //     } else {
                //         test(cb2);
                //     }
                // }, 10);
                mod.C_SignInit(item.session, {
                    mechanism: pkcs11.CKM_SHA1_RSA_PKCS,
                    parameter: null
                }, item.privateKey);
                mod.C_Sign(item.session, data, signature, function (err, sig) {
                    if (err) {
                        console.log(err);
                    }
                    refCount--;
                    if (!refCount) {
                        cb2();
                    }
                    else {
                        test(cb2);
                    }
                });
            }
            test(function () {
                sesRefCount--;
                if (!sesRefCount) {
                    sessions.forEach(function (item) {
                        mod.C_CloseSession(item.session);
                    });
                    var eTime = Date.now();
                    var time = (eTime - sTime) / 1000;
                    console.log("Total: " + time.toFixed(3) + ", per sec: " + (config.iterations / time).toFixed(3));
                    cb();
                }
            });
        })();
    };
    for (var i = 0; i < config.threads; i++) {
        _loop_1(i);
    }
}
console.log(config);
GenerateTestKeyPair();
console.time("Sign test");
TestSign(function () {
    RemoveTestKeyPair();
    console.timeEnd("Sign test");
    mod.C_CloseAllSessions(mod.C_GetSlotList()[config.slot]);
    mod.C_Finalize();
    console.log("success");
});
