const assert = require("assert");
const os = require("os");
const pkcs11 = require("../");

let softHsmLib;
switch (os.platform()) {
  case "darwin": // macOS
    softHsmLib = "/usr/local/lib/softhsm/libsofthsm2.so";
    break;
  case "linux":
    softHsmLib = "/usr/lib/softhsm/libsofthsm2.so";
    break;
  case "win32": // Windows
    softHsmLib = "C:\\SoftHSM2\\lib\\softhsm2-x64.dll";
    break;
  default:
    throw new Error("Unsupported platform " + os.platform());
}
const pin = "12345";

context("PKCS11", () => {
  context("load", () => {
    it("correct", () => {
      const token = new pkcs11.PKCS11();
      token.load(softHsmLib);
    });
    it("throw exception if file does not exist", () => {
      const token = new pkcs11.PKCS11();
      assert.throws(() => {
        token.load("/tmp/wrong/file/path.net");
      });
    });
  });
  context("C_Initialize, C_Finalize", () => {
    it("without params", () => {
      const token = new pkcs11.PKCS11();
      token.load(softHsmLib);
      token.C_Initialize();
      token.C_Finalize();
    });
    it("with params", () => {
      const token = new pkcs11.PKCS11();
      token.load(softHsmLib);
      token.C_Initialize({ flags: 0 });
      token.C_Finalize();
    });
    it("with NSS params", () => {
      const nssLib = os.platform() === "darwin" ? "/usr/local/opt/nss/lib/libsoftokn3.dylib" : "/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so";
      const token = new pkcs11.PKCS11();
      token.load(nssLib);
      token.C_Initialize({
        libraryParameters: "configdir='' certPrefix='' keyPrefix='' secmod='' flags=readOnly,noCertDB,noModDB,forceOpen,optimizeSpace",
      });
      token.C_Finalize();
    });
  });
  context("API", () => {
    let token;
    before(() => {
      token = new pkcs11.PKCS11();
      token.load(softHsmLib);
      token.C_Initialize();
    });
    after(() => {
      token.C_Finalize();
      token.close();
    });
    it("C_GetInfo", () => {
      const infoKeys = token.C_GetInfo();
      assert.deepStrictEqual(Object.keys(infoKeys), [
        "cryptokiVersion",
        "manufacturerID",
        "flags",
        "libraryDescription",
        "libraryVersion",
      ]);
      const cryptokiVersionKeys = Object.keys(infoKeys.cryptokiVersion);
      assert.deepEqual(cryptokiVersionKeys, ["major", "minor"]);
      const libraryVersionKeys = Object.keys(infoKeys.libraryVersion);
      assert.deepEqual(libraryVersionKeys, ["major", "minor"]);
    });
    it("C_GetSlotList", () => {
      const slots = token.C_GetSlotList();
      assert.strictEqual(slots.length > 0, true);
    });

    it("should throw error if amount of arguments is less than expected", () => {
      assert.throws(() => {
        token.C_GetSlotInfo();
      }, (e) => {
        assert.strictEqual(e instanceof TypeError, true);
        assert.strictEqual(e.message, "Parameters are required. Expected 1 arguments, but received 0.");
        return true;
      });
    });

    context("Slot", () => {
      let slot;
      before(() => {
        const slots = token.C_GetSlotList();
        slot = slots[0];
        assert.strictEqual(!!slot, true);
      });
      after(() => {
        token.C_CloseAllSessions(slot);
      });
      context("C_GetSlotInfo", () => {
        it("correct", () => {
          const info = token.C_GetSlotInfo(slot);
          assert.deepStrictEqual(Object.keys(info), [
            "slotDescription",
            "manufacturerID",
            "flags",
            "hardwareVersion",
            "firmwareVersion",
          ]);
          const hardwareVersionKeys = Object.keys(info.hardwareVersion);
          assert.deepEqual(hardwareVersionKeys, ["major", "minor"]);
          const firmwareVersionKeys = Object.keys(info.firmwareVersion);
          assert.deepEqual(firmwareVersionKeys, ["major", "minor"]);
        });
        it("should throw error if argument is not a Buffer", () => {
          assert.throws(() => {
            token.C_GetSlotInfo("wrong");
          }, (e) => {
            assert.strictEqual(e instanceof TypeError, true);
            assert.strictEqual(e.message, "Argument 0 has wrong type. Should be a Buffer");
            return true;
          });
        });
        it("should throw error if argument has wrong length", () => {
          assert.throws(() => {
            token.C_GetSlotInfo(Buffer.alloc(0));
          }, (e) => {
            assert.strictEqual(e instanceof TypeError, true);
            assert.strictEqual(e.message, "Argument 0 has wrong length. Should be 8 bytes.");
            return true;
          });
        });
      });
      it("C_GetTokenInfo", () => {
        const info = token.C_GetTokenInfo(slot);
        assert.deepStrictEqual(Object.keys(info), [
          "label",
          "manufacturerID",
          "model",
          "serialNumber",
          "flags",
          "maxSessionCount",
          "sessionCount",
          "maxRwSessionCount",
          "rwSessionCount",
          "maxPinLen",
          "minPinLen",
          "hardwareVersion",
          "firmwareVersion",
          "utcTime",
          "totalPublicMemory",
          "freePublicMemory",
          "totalPrivateMemory",
          "freePrivateMemory",
        ]);
        const hardwareVersionKeys = Object.keys(info.hardwareVersion);
        assert.deepEqual(hardwareVersionKeys, ["major", "minor"]);
        const firmwareVersionKeys = Object.keys(info.firmwareVersion);
        assert.deepEqual(firmwareVersionKeys, ["major", "minor"]);
        assert.ok(info.utcTime instanceof Date);
        assert.ok(typeof info.totalPublicMemory === 'bigint');
        assert.ok(typeof info.freePublicMemory === 'bigint');
        assert.ok(typeof info.totalPrivateMemory === 'bigint');
        assert.ok(typeof info.freePrivateMemory === 'bigint');
      });
      it("C_GetMechanismList", () => {
        const mechanisms = token.C_GetMechanismList(slot);
        assert.strictEqual(mechanisms.length > 0, true);
      });
      it("C_GetMechanismInfo", () => {
        const mechanisms = token.C_GetMechanismList(slot);
        const info = token.C_GetMechanismInfo(slot, mechanisms[0]);
        assert.deepStrictEqual(Object.keys(info), [
          "minKeySize",
          "maxKeySize",
          "flags",
        ]);
      });
      context("Session", () => {
        let session;
        before(() => {
          session = token.C_OpenSession(slot, pkcs11.CKF_RW_SESSION | pkcs11.CKF_SERIAL_SESSION);
        });
        after(() => {
          token.C_CloseSession(session);
        });
        it("C_GetSessionInfo", () => {
          const info = token.C_GetSessionInfo(session);
          assert.deepStrictEqual(Object.keys(info), [
            "slotID",
            "state",
            "flags",
            "deviceError",
          ]);
        });
        it("C_GetOperationState", () => {
          try {
            const state = token.C_GetOperationState(session);
            assert.ok(Buffer.isBuffer(state));
          } catch (e) {
            if (!(e instanceof pkcs11.Pkcs11Error)) {
              throw e;
            }
          }
        });
        it("C_SetOperationState", () => {
          try {
            token.C_SetOperationState(session, Buffer.alloc(8), Buffer.alloc(8), Buffer.alloc(8));
          } catch (e) {
            if (!(e instanceof pkcs11.Pkcs11Error)) {
              throw e;
            }
          }
        });
        it("C_Login/C_Logout", () => {
          token.C_Login(session, pkcs11.CKU_USER, "12345");
          token.C_Logout(session);
        });
        it("C_GenerateRandom", () => {
          const buf = Buffer.alloc(10);
          const buf2 = token.C_GenerateRandom(session, buf);
          assert.strictEqual(buf, buf2);
          assert.notStrictEqual(buf.toString("hex"), "00000000000000000000");
        });
        it("C_SeedRandom", () => {
          const buf = Buffer.alloc(10);
          token.C_SeedRandom(session, buf);
        });
        context("Find", () => {
          const label = Buffer.from("Find");
          before(() => {
            token.C_Login(session, pkcs11.CKU_USER, pin);
            // 1
            token.C_CreateObject(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
              { type: pkcs11.CKA_LABEL, value: label },
              { type: pkcs11.CKA_VALUE, value: Buffer.from("data") },
            ]);
            // 2
            token.C_CreateObject(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
              { type: pkcs11.CKA_LABEL, value: label },
              { type: pkcs11.CKA_VALUE, value: Buffer.from("data") },
            ]);
            // 3
            token.C_CreateObject(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
              { type: pkcs11.CKA_LABEL, value: label },
              { type: pkcs11.CKA_VALUE, value: Buffer.from("data") },
            ]);
          });
          after(() => {
            token.C_Logout(session);
          });
          it("Find single object", () => {
            token.C_FindObjectsInit(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
              { type: pkcs11.CKA_LABEL, value: label },
            ]);
            let handle = token.C_FindObjects(session);
            assert.strictEqual(Buffer.isBuffer(handle), true);
            handle = token.C_FindObjects(session);
            assert.strictEqual(Buffer.isBuffer(handle), true);
            handle = token.C_FindObjects(session);
            assert.strictEqual(Buffer.isBuffer(handle), true);
            handle = token.C_FindObjects(session);
            assert.strictEqual(handle, null);
            token.C_FindObjectsFinal(session);
          });
          it("Find multi objects", () => {
            token.C_FindObjectsInit(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
              { type: pkcs11.CKA_LABEL, value: label },
            ]);
            let handles = token.C_FindObjects(session, 2);
            assert.strictEqual(handles.length, 2);
            handles = token.C_FindObjects(session, 2);
            assert.strictEqual(handles.length, 1);
            token.C_FindObjectsFinal(session);
          });
        });
        context("C_CopyObject", () => {
          before(() => {
            token.C_Login(session, pkcs11.CKU_USER, pin);
          });
          after(() => {
            token.C_Logout(session);
          });
          it("Copy", () => {
            const label = Buffer.from("Copy");
            const obj = token.C_CreateObject(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
              { type: pkcs11.CKA_LABEL, value: label },
              { type: pkcs11.CKA_VALUE, value: Buffer.from("data") },
            ]);
            const obj2 = token.C_CopyObject(session, obj, [
              { type: pkcs11.CKA_LABEL, value: label },
            ]);
            assert.notEqual(obj.toString("hex"), obj2.toString("hex"));
          });
        });
        context("Attribute", () => {
          let obj;
          const label = Buffer.from("Attribute");
          before(() => {
            token.C_Login(session, pkcs11.CKU_USER, pin);
            obj = token.C_CreateObject(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
              { type: pkcs11.CKA_LABEL, value: label },
              { type: pkcs11.CKA_VALUE, value: Buffer.from("data") },
            ]);
          });
          after(() => {
            token.C_Logout(session);
          });
          it("C_GetAttributeValue", () => {
            const attrs = token.C_GetAttributeValue(session, obj, [
              { type: pkcs11.CKA_CLASS },
              { type: pkcs11.CKA_LABEL },
              { type: pkcs11.CKA_VALUE },
            ]);
            assert.strictEqual(attrs.length, 3);
            assert.strictEqual(attrs[0].type, pkcs11.CKA_CLASS);
            assert.strictEqual(attrs[0].value.toString("hex"), Buffer.alloc(8).toString("hex"));
            assert.strictEqual(attrs[1].type, pkcs11.CKA_LABEL);
            assert.strictEqual(attrs[1].value.toString("hex"), label.toString("hex"));
            assert.strictEqual(attrs[2].type, pkcs11.CKA_VALUE);
            assert.strictEqual(attrs[2].value.toString("hex"), Buffer.from("data").toString("hex"));
          });
          context("C_SetAttributeValue", () => {
            it("Boolean", () => {
              token.C_SetAttributeValue(session, obj, [
                { type: pkcs11.CKA_LABEL, value: true },
              ]);
              const attrs = token.C_GetAttributeValue(session, obj, [
                { type: pkcs11.CKA_LABEL },
              ]);
              assert.strictEqual(attrs.length, 1);
              assert.strictEqual(attrs[0].type, pkcs11.CKA_LABEL);
              assert.strictEqual(attrs[0].value.toString("hex"), Buffer.from([1]).toString("hex"));
            });
            it("Number", () => {
              token.C_SetAttributeValue(session, obj, [
                { type: pkcs11.CKA_LABEL, value: 1 },
              ]);
              const attrs = token.C_GetAttributeValue(session, obj, [
                { type: pkcs11.CKA_LABEL },
              ]);
              assert.strictEqual(attrs.length, 1);
              assert.strictEqual(attrs[0].type, pkcs11.CKA_LABEL);
              assert.strictEqual(attrs[0].value.toString("hex"), Buffer.from([1, 0, 0, 0, 0, 0, 0, 0]).toString("hex"));
            });
            it("String", () => {
              token.C_SetAttributeValue(session, obj, [
                { type: pkcs11.CKA_LABEL, value: "new label" },
              ]);
              const attrs = token.C_GetAttributeValue(session, obj, [
                { type: pkcs11.CKA_LABEL },
              ]);
              assert.strictEqual(attrs.length, 1);
              assert.strictEqual(attrs[0].type, pkcs11.CKA_LABEL);
              assert.strictEqual(attrs[0].value.toString(), "new label");
            });
            it("Buffer", () => {
              token.C_SetAttributeValue(session, obj, [
                { type: pkcs11.CKA_LABEL, value: Buffer.from("new label") },
              ]);
              const attrs = token.C_GetAttributeValue(session, obj, [
                { type: pkcs11.CKA_LABEL },
              ]);
              assert.strictEqual(attrs.length, 1);
              assert.strictEqual(attrs[0].type, pkcs11.CKA_LABEL);
              assert.strictEqual(attrs[0].value.toString("hex"), Buffer.from("new label").toString("hex"));
            });
          });
        });
        context("C_GenerateKey", () => {
          let session;
          before(() => {
            session = token.C_OpenSession(slot, pkcs11.CKF_RW_SESSION | pkcs11.CKF_SERIAL_SESSION);
            token.C_Login(session, pkcs11.CKU_USER, pin);
          });
          after(() => {
            token.C_Logout(session);
            token.C_CloseSession(session);
          });
          it("AES", () => {
            const key = token.C_GenerateKey(session, { mechanism: pkcs11.CKM_AES_KEY_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
              { type: pkcs11.CKA_VALUE_LEN, value: 16 },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_DECRYPT, value: true },
            ]);
            assert.strictEqual(Buffer.isBuffer(key), true);
          });
          it("AES with callback", (done) => {
            token.C_GenerateKey(session, { mechanism: pkcs11.CKM_AES_KEY_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
              { type: pkcs11.CKA_VALUE_LEN, value: 16 },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_DECRYPT, value: true },
            ], (error, key) => {
              if (error) {
                done(error);
                return;
              }
              assert.strictEqual(Buffer.isBuffer(key), true);
              done();
            });
          });
          it("AES with async", async () => {
            const key = await token.C_GenerateKeyAsync(session, { mechanism: pkcs11.CKM_AES_KEY_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
              { type: pkcs11.CKA_VALUE_LEN, value: 16 },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_DECRYPT, value: true },
            ]);
            assert.strictEqual(Buffer.isBuffer(key), true);
          });
        });
        context("C_GenerateKeyPair", () => {
          let session;
          before(() => {
            session = token.C_OpenSession(slot, pkcs11.CKF_RW_SESSION | pkcs11.CKF_SERIAL_SESSION);
            token.C_Login(session, pkcs11.CKU_USER, pin);
          });
          after(() => {
            token.C_Logout(session);
            token.C_CloseSession(session);
          });
          it("RSA", () => {
            const keys = token.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
              { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([1, 0, 1]) },
              { type: pkcs11.CKA_MODULUS_BITS, value: 2048 },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_VERIFY, value: true },
            ], [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
              { type: pkcs11.CKA_DECRYPT, value: true },
              { type: pkcs11.CKA_SIGN, value: true },
            ]);
            assert.strictEqual(Buffer.isBuffer(keys.publicKey), true);
            assert.strictEqual(Buffer.isBuffer(keys.privateKey), true);
          });
          it("RSA with callback", (done) => {
            token.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
              { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([1, 0, 1]) },
              { type: pkcs11.CKA_MODULUS_BITS, value: 2048 },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_VERIFY, value: true },
            ], [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
              { type: pkcs11.CKA_DECRYPT, value: true },
              { type: pkcs11.CKA_SIGN, value: true },
            ], (error, keys) => {
              if (error) {
                done(error);
                return;
              }
              assert.strictEqual(Buffer.isBuffer(keys.publicKey), true);
              assert.strictEqual(Buffer.isBuffer(keys.privateKey), true);
              done();
            });
          });
          it("RSA with async", async () => {
            const keys = await token.C_GenerateKeyPairAsync(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
              { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([1, 0, 1]) },
              { type: pkcs11.CKA_MODULUS_BITS, value: 2048 },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_VERIFY, value: true },
            ], [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
              { type: pkcs11.CKA_DECRYPT, value: true },
              { type: pkcs11.CKA_SIGN, value: true },
            ]);
            assert.strictEqual(Buffer.isBuffer(keys.publicKey), true);
            assert.strictEqual(Buffer.isBuffer(keys.privateKey), true);
          });
        });
        context("Digest (SHA-256)", () => {
          before(() => {
            token.C_Login(session, pkcs11.CKU_USER, pin);
          });
          after(() => {
            token.C_Logout(session);
          });
          afterEach(() => {
            try {
              token.C_DigestFinal(session, Buffer.alloc(40));
            } catch (e) {
              // ignore
            }
          });
          it("C_DigestInit, C_Digest", () => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            const hash2 = token.C_Digest(session, data, hash);
            assert.strictEqual(hash.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d0000000000000000");
            assert.strictEqual(hash2.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
          });
          it("C_DigestInit, C_Digest callback", (done) => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            token.C_Digest(session, data, hash, (error, hash2) => {
              if (error) {
                done(data);
              }
              else {
                assert.strictEqual(hash2.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
                done();
              }
            });
          });
          it("C_DigestInit, C_Digest async", async () => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            const hash2 = await token.C_DigestAsync(session, data, hash);
            assert.strictEqual(hash2.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
          });
          it("C_DigestInit, C_DigestUpdate, C_DigestFinal", () => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            token.C_DigestUpdate(session, data);
            const hash2 = token.C_DigestFinal(session, hash);
            assert.strictEqual(hash.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d0000000000000000");
            assert.strictEqual(hash2.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
          });
          it("C_DigestInit, C_DigestUpdate, C_DigestKey, C_DigestFinal", () => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            const hmacKey = token.C_GenerateKey(session, { mechanism: pkcs11.CKM_GENERIC_SECRET_KEY_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
              { type: pkcs11.CKA_VALUE_LEN, value: 8 },
              { type: pkcs11.CKA_SIGN, value: true },
              { type: pkcs11.CKA_VERIFY, value: true },
            ]);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            token.C_DigestUpdate(session, data);
            token.C_DigestKey(session, hmacKey);
            const hash2 = token.C_DigestFinal(session, hash);
            assert.strictEqual(/^0{80}$/.test(hash.toString("hex")), false);
            assert.strictEqual(/^[a-f0-9]{64}0000000000000000$/.test(hash.toString("hex")), true);
            assert.strictEqual(/^[a-f0-9]{64}$/.test(hash2.toString("hex")), true);
            assert.strictEqual(hash.toString("hex").startsWith(hash2.toString("hex")), true);
          });
          it("C_DigestInit, C_DigestUpdate, C_DigestFinal with callback", (done) => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            token.C_DigestUpdate(session, data);
            const hash2 = token.C_DigestFinalCallback(session, hash, (error, hash2) => {
              assert.strictEqual(/^0{80}$/.test(hash.toString("hex")), false);
              assert.strictEqual(/^[a-f0-9]{64}0000000000000000$/.test(hash.toString("hex")), true);
              assert.strictEqual(/^[a-f0-9]{64}$/.test(hash2.toString("hex")), true);
              assert.strictEqual(hash.toString("hex").startsWith(hash2.toString("hex")), true);
              done();
            });
          });
          it("C_DigestInit, C_DigestUpdate, C_DigestFinal with callback error", (done) => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(4);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            token.C_DigestUpdate(session, data);
            token.C_DigestFinalCallback(session, hash, (error, hash2) => {
              assert.strictEqual(error instanceof pkcs11.Pkcs11Error, true);
              assert.strictEqual(error.message, "CKR_BUFFER_TOO_SMALL");
              assert.strictEqual(hash2, null);
              done();
            });
          });
          it("C_DigestInit, C_DigestUpdate, C_DigestFinal with async", async () => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            token.C_DigestUpdate(session, data);
            const hash2 = await token.C_DigestFinalAsync(session, hash);
            assert.strictEqual(/^0{80}$/.test(hash.toString("hex")), false);
            assert.strictEqual(/^[a-f0-9]{64}0000000000000000$/.test(hash.toString("hex")), true);
            assert.strictEqual(/^[a-f0-9]{64}$/.test(hash2.toString("hex")), true);
            assert.strictEqual(hash.toString("hex").startsWith(hash2.toString("hex")), true);
          });
        });
        context("Sign/Verify (RSA SHA-1, SHA-256)", () => {
          let keys;
          const data = Buffer.from("12345678901234567890");
          let rsaPkcsSignature;
          let rsaPkcsSha256Signature;
          before(() => {
            token.C_Login(session, pkcs11.CKU_USER, pin);
            keys = token.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
              { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([1, 0, 1]) },
              { type: pkcs11.CKA_MODULUS_BITS, value: 2048 },
              { type: pkcs11.CKA_VERIFY, value: true },
            ], [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
              { type: pkcs11.CKA_SIGN, value: true },
            ]);
          });
          before(() => {
            token.C_SignInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.privateKey);
            rsaPkcsSignature = token.C_Sign(session, data, Buffer.alloc(1024));
          });
          before(() => {
            token.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.privateKey);
            rsaPkcsSha256Signature = token.C_Sign(session, data, Buffer.alloc(1024));
          });
          after(() => {
            token.C_Logout(session);
          });
          it("C_SignInit, C_Sign", () => {
            const signature = Buffer.alloc(1024);
            token.C_SignInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.privateKey);
            const signature2 = token.C_Sign(session, data, signature);
            assert.strictEqual(signature2.length < signature.length, true);
            assert.strictEqual(signature2.toString("hex"), signature.slice(0, signature2.length).toString("hex"));
          });
          it("C_SignInit, C_Sign callback", (done) => {
            const signature = Buffer.alloc(1024);
            token.C_SignInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.privateKey);
            token.C_Sign(session, data, signature, (error, signature2) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(signature2.length < signature.length, true);
                done();
              }
            });
          });
          it("C_SignInit, C_Sign async", async () => {
            const signature = Buffer.alloc(1024);
            token.C_SignInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.privateKey);
            const signature2 = await token.C_SignAsync(session, data, signature);
            assert.strictEqual(signature2.length < signature.length, true);
          });
          it("C_SignInit, C_SignUpdate, C_SignFinal", () => {
            const signature = Buffer.alloc(1024);
            token.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.privateKey);
            token.C_SignUpdate(session, data);
            const signature2 = token.C_SignFinal(session, signature);
            assert.strictEqual(signature2.length < signature.length, true);
            assert.strictEqual(signature2.toString("hex"), signature.slice(0, signature2.length).toString("hex"));
          });
          it("C_SignInit, C_SignUpdate, C_SignFinal callback", (done) => {
            const signature = Buffer.alloc(1024);
            token.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.privateKey);
            token.C_SignUpdate(session, data);
            token.C_SignFinal(session, signature, (error, signature2) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(signature2.length < signature.length, true);
                done();
              }
            });
          });
          it("C_SignInit, C_SignUpdate, C_SignFinal async", async () => {
            const signature = Buffer.alloc(1024);
            token.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.privateKey);
            token.C_SignUpdate(session, data);
            const signature2 = await token.C_SignFinalAsync(session, signature);
            assert.strictEqual(signature2.length < signature.length, true);
          });
          it("C_VerifyInit, C_Verify", () => {
            token.C_VerifyInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.publicKey);
            const ok = token.C_Verify(session, data, rsaPkcsSignature);
            assert.strictEqual(ok, true);
          });
          it("C_VerifyInit, C_Verify callback", (done) => {
            token.C_VerifyInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.publicKey);
            token.C_Verify(session, data, rsaPkcsSignature, (error, ok) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(ok, true);
                done();
              }
            });
          });
          it("C_VerifyInit, C_Verify async", async () => {
            token.C_VerifyInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.publicKey);
            const ok = await token.C_VerifyAsync(session, data, rsaPkcsSignature);
            assert.strictEqual(ok, true);
          });
          it("C_VerifyInit, C_VerifyUpdate, C_VerifyFinal", () => {
            token.C_VerifyInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.publicKey);
            token.C_VerifyUpdate(session, data);
            const ok = token.C_VerifyFinal(session, rsaPkcsSha256Signature);
            assert.strictEqual(ok, true);
          });
          it("C_VerifyInit, C_VerifyUpdate, C_VerifyFinal callback", (done) => {
            token.C_VerifyInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.publicKey);
            token.C_VerifyUpdate(session, data);
            token.C_VerifyFinal(session, rsaPkcsSha256Signature, (error, ok) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(ok, true);
                done();
              }
            });
          });
          it("C_VerifyInit, C_VerifyUpdate, C_VerifyFinal async", async () => {
            token.C_VerifyInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.publicKey);
            token.C_VerifyUpdate(session, data);
            const ok = await token.C_VerifyFinalAsync(session, rsaPkcsSha256Signature);
            assert.strictEqual(ok, true);
          });
        });
        // https://github.com/PeculiarVentures/pkcs11js/issues/47
        (os.platform() === "linux" && +/v(\d+)/.exec(process.version)[1] > 9
          ? context.skip
          : context)("Encrypt/Decrypt RSA-OAEP", () => {
            let keys;
            before(() => {
              token.C_Login(session, pkcs11.CKU_USER, pin);
              // private key
              keys = token.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, [
                { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
                { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([1, 0, 1]) },
                { type: pkcs11.CKA_MODULUS_BITS, value: 2048 },
                { type: pkcs11.CKA_ENCRYPT, value: true },
              ], [
                { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
                { type: pkcs11.CKA_DECRYPT, value: true },
              ]);
              // public key
            });
            after(() => {
              token.C_Logout(session);
            });
            it("OAEP without label", () => {
              const mechanism = {
                mechanism: pkcs11.CKM_RSA_PKCS_OAEP,
                parameter: {
                  type: pkcs11.CK_PARAMS_RSA_OAEP,
                  hashAlg: pkcs11.CKM_SHA_1,
                  mgf: pkcs11.CKG_MGF1_SHA1,
                  source: 1,
                  sourceData: null, // SoftHSM v2.0.5 doesn't support sourceData parameter
                  // sourceData: Buffer.from("1234567890abcdef"),
                }
              };
              const data = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);
              token.C_EncryptInit(session, mechanism, keys.publicKey);
              const enc = token.C_Encrypt(session, data, Buffer.alloc(4098));

              token.C_DecryptInit(session, mechanism, keys.privateKey);
              const dec = token.C_Decrypt(session, enc, Buffer.alloc(1024));
              assert.strictEqual(data.equals(dec), true);
            })
          });
        context("Encrypt/Decrypt (AES-CBC)", () => {
          let key;
          const data = Buffer.from("12345678901234567890");
          const parameter = Buffer.from("1234567890abcdef");
          let encrypted;
          before(() => {
            token.C_Login(session, pkcs11.CKU_USER, pin);
            key = token.C_CreateObject(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
              { type: pkcs11.CKA_VALUE, value: parameter },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_DECRYPT, value: true },
            ]);
          });
          before(() => {
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            encrypted = token.C_Encrypt(session, data, Buffer.alloc(1024));
          });
          after(() => {
            token.C_Logout(session);
          });
          beforeEach(() => {
            try {
              token.C_DecryptFinal(session, Buffer.alloc(40));
            } catch (e) {
              // ignore
            }
          });
          it("C_EncryptInit, C_Encrypt", () => {
            const enc = Buffer.alloc(1024);
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            const enc2 = token.C_Encrypt(session, data, enc);
            assert.strictEqual(enc2.length < enc.length, true);
            assert.strictEqual(enc2.toString("hex"), enc.slice(0, enc2.length).toString("hex"));
          });
          it("C_EncryptInit, C_Encrypt callback", (done) => {
            const enc = Buffer.alloc(1024);
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            token.C_Encrypt(session, data, enc, (error, enc2) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(enc2.length < enc.length, true);
                done();
              }
            });
          });
          it("C_EncryptInit, C_Encrypt async", async () => {
            const enc = Buffer.alloc(1024);
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            const enc2 = await token.C_EncryptAsync(session, data, enc);
            assert.strictEqual(enc2.length < enc.length, true);
          });
          it("C_EncryptInit, C_EncryptUpdate, C_EncryptFinal", () => {
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            let enc = token.C_EncryptUpdate(session, data, Buffer.alloc(128));
            enc = Buffer.concat([enc, token.C_EncryptFinal(session, Buffer.alloc(128))]);
            assert.strictEqual(enc.length > 0, true);
          });
          it("C_EncryptInit, C_EncryptUpdate, C_EncryptFinal callback", (done) => {
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            token.C_EncryptUpdate(session, data, Buffer.alloc(128));
            token.C_EncryptFinal(session, Buffer.alloc(128), (error, enc) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(enc.length > 0, true);
                done();
              }
            });
          });
          it("C_EncryptInit, C_EncryptUpdate, C_EncryptFinal async", async () => {
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            token.C_EncryptUpdate(session, data, Buffer.alloc(128));
            const enc = await token.C_EncryptFinalAsync(session, Buffer.alloc(128));
            assert.strictEqual(enc.length > 0, true);
          });
          it("C_DecryptInit, C_Decrypt", () => {
            const dec = Buffer.alloc(1024);
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            const dec2 = token.C_Decrypt(session, encrypted, dec);
            assert.strictEqual(dec2.length < dec.length, true);
            assert.strictEqual(dec2.toString("hex"), dec.subarray(0, dec2.length).toString("hex"));
          });
          it("C_DecryptInit, C_Decrypt callback", (done) => {
            const dec = Buffer.alloc(1024);
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            token.C_Decrypt(session, encrypted, dec, (error, dec2) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(dec2.length < dec.length, true);
                done();
              }
            });
          });
          it("C_DecryptInit, C_Decrypt async", async () => {
            const dec = Buffer.alloc(1024);
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            const dec2 = await token.C_DecryptAsync(session, encrypted, dec);
            assert.strictEqual(dec2.toString(), data.toString());
          });
          it("C_DecryptInit, C_DecryptUpdate, C_DecryptFinal", () => {
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            let dec = token.C_DecryptUpdate(session, encrypted, Buffer.alloc(128));
            dec = Buffer.concat([dec, token.C_DecryptFinal(session, Buffer.alloc(128))]);
            assert.strictEqual(dec.length > 0, true);
          });
          it("C_DecryptInit, C_DecryptUpdate, C_DecryptFinal callback", (done) => {
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            token.C_DecryptUpdate(session, encrypted, Buffer.alloc(128));
            token.C_DecryptFinal(session, Buffer.alloc(128), (error, dec) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(dec.length > 0, true);
                done();
              }
            });
          });
          it("C_DecryptInit, C_DecryptUpdate, C_DecryptFinal async", async () => {
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            token.C_DecryptUpdate(session, encrypted, Buffer.alloc(128));
            const dec = await token.C_DecryptFinalAsync(session, Buffer.alloc(128));
            assert.strictEqual(dec.length > 0, true);
          });
        });
        context("Derive (ECDH secp256k1)", () => {
          let keys;
          before(() => {
            token.C_Login(session, pkcs11.CKU_USER, pin);
            keys = token.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_ECDSA_KEY_PAIR_GEN }, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
              { type: pkcs11.CKA_ECDSA_PARAMS, value: Buffer.from([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A]) },
              { type: pkcs11.CKA_DERIVE, value: true },
            ], [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
              { type: pkcs11.CKA_DERIVE, value: true },
            ]);
          });
          it("C_DeriveKey", () => {
            const key = token.C_DeriveKey(session, {
              mechanism: pkcs11.CKM_ECDH1_DERIVE,
              parameter: {
                type: pkcs11.CK_PARAMS_EC_DH,
                kdf: pkcs11.CKD_NULL,
                publicData: token.C_GetAttributeValue(session, keys.publicKey, [{ type: pkcs11.CKA_EC_POINT }])[0].value,
              },
            }, keys.privateKey, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_VALUE_LEN, value: 16 },
            ]);
            assert.strictEqual(!!key, true);
          });
          it("C_DeriveKey callback", (done) => {
            token.C_DeriveKey(session, {
              mechanism: pkcs11.CKM_ECDH1_DERIVE,
              parameter: {
                type: pkcs11.CK_PARAMS_EC_DH,
                kdf: pkcs11.CKD_NULL,
                publicData: token.C_GetAttributeValue(session, keys.publicKey, [{ type: pkcs11.CKA_EC_POINT }])[0].value,
              },
            }, keys.privateKey, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_VALUE_LEN, value: 16 },
            ], (error, key) => {
              if (error) {
                done(error);
              }
              else {
                assert.strictEqual(Buffer.isBuffer(key), true);
                done();
              }
            });
          });
          it("C_DeriveKey async", async () => {
            const key = await token.C_DeriveKeyAsync(session, {
              mechanism: pkcs11.CKM_ECDH1_DERIVE,
              parameter: {
                type: pkcs11.CK_PARAMS_EC_DH,
                kdf: pkcs11.CKD_NULL,
                publicData: token.C_GetAttributeValue(session, keys.publicKey, [{ type: pkcs11.CKA_EC_POINT }])[0].value,
              },
            }, keys.privateKey, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
              { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
              { type: pkcs11.CKA_ENCRYPT, value: true },
              { type: pkcs11.CKA_VALUE_LEN, value: 16 },
            ]);
            assert.strictEqual(Buffer.isBuffer(key), true);
          });
        });
      });
      context("Wrap/Unwrap (AES)", () => {
        let session
        let key;
        const label = Buffer.from("WrapKey");
        before(() => {
          session = token.C_OpenSession(slot, pkcs11.CKF_RW_SESSION | pkcs11.CKF_SERIAL_SESSION);
          token.C_Login(session, pkcs11.CKU_USER, pin);
          key = token.C_GenerateKey(session, { mechanism: pkcs11.CKM_AES_KEY_GEN }, [
            { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
            { type: pkcs11.CKA_LABEL, value: label },
            { type: pkcs11.CKA_ENCRYPT, value: true },
            { type: pkcs11.CKA_DECRYPT, value: true },
            { type: pkcs11.CKA_WRAP, value: true },
            { type: pkcs11.CKA_UNWRAP, value: true },
            { type: pkcs11.CKA_VALUE_LEN, value: 16 },
            { type: pkcs11.CKA_EXTRACTABLE, value: true },
          ]);
        });
        after(() => {
          token.C_Logout(session);
          token.C_CloseSession(session);
        });
        it("C_WrapKey, C_UnwrapKey", () => {
          const mechanism = { mechanism: pkcs11.CKM_AES_KEY_WRAP_PAD };

          const wrapped = token.C_WrapKey(session, mechanism, key, key, Buffer.alloc(1024));
          assert.strictEqual(wrapped.length > 0 && wrapped.length < 1024, true);
          const unwrappedKey = token.C_UnwrapKey(session, mechanism, key, wrapped, [
            { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
            { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
            { type: pkcs11.CKA_ENCRYPT, value: true },
            { type: pkcs11.CKA_DECRYPT, value: true },
          ]);
          assert.strictEqual(!!unwrappedKey, true);
        });
        it("C_WrapKey, C_UnwrapKey callback", (done) => {
          const mechanism = { mechanism: pkcs11.CKM_AES_KEY_WRAP_PAD };

          token.C_WrapKey(session, mechanism, key, key, Buffer.alloc(1024), (error, wrapped) => {
            if (error) {
              done(error);
            }
            else {
              assert.strictEqual(wrapped.length > 0 && wrapped.length < 1024, true);
              token.C_UnwrapKey(session, mechanism, key, wrapped, [
                { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
                { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
                { type: pkcs11.CKA_ENCRYPT, value: true },
                { type: pkcs11.CKA_DECRYPT, value: true },
              ], (error, unwrappedKey) => {
                if (error) {
                  done(error);
                }
                else {
                  assert.strictEqual(Buffer.isBuffer(unwrappedKey), true);
                  done();
                }
              });
            }
          });
        });
        it("C_WrapKey, C_UnwrapKey async", async () => {
          const mechanism = { mechanism: pkcs11.CKM_AES_KEY_WRAP_PAD };

          const wrapped = await token.C_WrapKeyAsync(session, mechanism, key, key, Buffer.alloc(1024));
          assert.strictEqual(wrapped.length > 0 && wrapped.length < 1024, true);
          const unwrappedKey = await token.C_UnwrapKeyAsync(session, mechanism, key, wrapped, [
            { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
            { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
            { type: pkcs11.CKA_ENCRYPT, value: true },
            { type: pkcs11.CKA_DECRYPT, value: true },
          ]);
          assert.strictEqual(Buffer.isBuffer(unwrappedKey), true);
        });
      });
    });
  });
  context("native error", () => {
    it("with Cryptoki result value", () => {
      const token = new pkcs11.PKCS11();
      token.load(softHsmLib);
      assert.throws(() => {
        token.C_Finalize();
      }, (e) => {
        assert.strictEqual(e instanceof pkcs11.Pkcs11Error, true);
        assert.strictEqual(e.name, pkcs11.Pkcs11Error.name);
        assert.strictEqual(e.message, "CKR_CRYPTOKI_NOT_INITIALIZED");
        assert.strictEqual(e.method, "C_Finalize");
        assert.strictEqual(e.code, pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED);
        assert.strictEqual(/C_Finalize/.test(e.nativeStack), true)

        return true;
      });
    });
    it("without Cryptoki result value", () => {
      const token = new pkcs11.PKCS11();
      token.load(softHsmLib);
      assert.throws(() => {
        token.C_Initialize("wrong");
      }, (e) => {
        assert.strictEqual(e instanceof TypeError, true);
        assert.strictEqual(e.message, "Argument 0 has wrong type. Should be an Object");

        return true;
      });
    });
    context("callback", () => {
      let token, session;

      before(() => {
        token = new pkcs11.PKCS11();
        token.load(softHsmLib);
        token.C_Initialize();
        const slots = token.C_GetSlotList();
        const slot = slots[0];
        session = token.C_OpenSession(slot, pkcs11.CKF_RW_SESSION | pkcs11.CKF_SERIAL_SESSION)
        token.C_Login(session, pkcs11.CKU_USER, pin);
      });

      after(() => {
        if (session) {
          token.C_Finalize();
        }
      });

      it("Pkcs11Error", (done) => {
        token.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, [], [], (error) => {
          assert.strictEqual(error instanceof pkcs11.Pkcs11Error, true);
          assert.strictEqual(error.code, pkcs11.CKR_TEMPLATE_INCOMPLETE);
          done();
        });
      });
    });
    context("async", () => {
      let token, session;

      before(() => {
        token = new pkcs11.PKCS11();
        token.load(softHsmLib);
        token.C_Initialize();
        const slots = token.C_GetSlotList();
        const slot = slots[0];
        session = token.C_OpenSession(slot, pkcs11.CKF_RW_SESSION | pkcs11.CKF_SERIAL_SESSION)
        token.C_Login(session, pkcs11.CKU_USER, pin);
      });

      after(() => {
        if (session) {
          token.C_Finalize();
        }
      });

      it("Pkcs11Error", async () => {
        await assert.rejects(token.C_GenerateKeyPairAsync(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, [], []), (e) => {
          assert.strictEqual(e instanceof pkcs11.Pkcs11Error, true);
          assert.strictEqual(e.code, pkcs11.CKR_TEMPLATE_INCOMPLETE);

          return true;
        });
      });

      it("TypeError", async () => {
        await assert.rejects(token.C_GenerateKeyPairAsync(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, [], "wrong argument"), (e) => {
          assert.strictEqual(e instanceof TypeError, true);

          return true;
        });
      });

      it("NativeError", async () => {
        const mod = new pkcs11.PKCS11();

        assert.throws(() => mod.C_GetInfo(), (e) => {
          assert.strictEqual(e instanceof pkcs11.NativeError, true);
          assert.strictEqual(e.message, "PKCS11 module not loaded yet");

          return true;
        });

      });
    });
  });

  it("call functions without loading the library", () => {
    const mod = new pkcs11.PKCS11();

    assert.throws(() => mod.C_GetInfo());
  })
});
