const assert = require("assert");
const os = require("os");
const pkcs11 = require("../");

const softHsmLib = "/usr/local/lib/softhsm/libsofthsm2.so";
const pin = "12345";

context("PKCS11", () => {
  context("load", () => {
    it("correct", () => {
      const token = new pkcs11.PKCS11();
      token.load(softHsmLib);
    });
    it("throw esxception if file does not exist", () => {
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
      const info = token.C_GetInfo();
      assert.deepEqual(Object.keys(info), [
        "cryptokiVersion",
        "manufacturerID",
        "flags",
        "libraryDescription",
        "libraryVersion",
      ]);
    });
    it("C_GetSlotList", () => {
      const slots = token.C_GetSlotList();
      assert.equal(slots.length > 0, true);
    });
    context("Slot", () => {
      let slot;
      before(() => {
        const slots = token.C_GetSlotList();
        slot = slots[0];
        assert.equal(!!slot, true);
      });
      after(() => {
        token.C_CloseAllSessions(slot);
      });
      it("C_GetSlotInfo", () => {
        const info = token.C_GetSlotInfo(slot);
        assert.deepEqual(Object.keys(info), [
          "slotDescription",
          "manufacturerID",
          "flags",
          "hardwareVersion",
          "firmwareVersion",
        ]);
      });
      it("C_GetTokenInfo", () => {
        const info = token.C_GetTokenInfo(slot);
        assert.deepEqual(Object.keys(info), [
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
      });
      it("C_GetMechanismList", () => {
        const mechanisms = token.C_GetMechanismList(slot);
        assert.equal(mechanisms.length > 0, true);
      });
      it("C_GetMechanismInfo", () => {
        const mechanisms = token.C_GetMechanismList(slot);
        const info = token.C_GetMechanismInfo(slot, mechanisms[0]);
        assert.deepEqual(Object.keys(info), [
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
          assert.deepEqual(Object.keys(info), [
            "slotID",
            "state",
            "flags",
            "deviceError",
          ]);
        });
        it("C_GenerateRandom", () => {
          const buf = Buffer.alloc(10);
          const buf2 = token.C_GenerateRandom(session, buf);
          assert.equal(buf, buf2);
          assert.notEqual(buf.toString("hex"), "00000000000000000000");
        });
        it.skip("C_SeedRandom", () => {
          const buf = Buffer.from("1234567890");
          const buf2 = token.C_SeedRandom(session, buf);
          assert.notEqual(buf.toString(), "1234567890");
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
            assert.equal(Buffer.isBuffer(handle), true);
            handle = token.C_FindObjects(session);
            assert.equal(Buffer.isBuffer(handle), true);
            handle = token.C_FindObjects(session);
            assert.equal(Buffer.isBuffer(handle), true);
            handle = token.C_FindObjects(session);
            assert.equal(handle, null);
            token.C_FindObjectsFinal(session);
          });
          it("Find multi objects", () => {
            token.C_FindObjectsInit(session, [
              { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
              { type: pkcs11.CKA_LABEL, value: label },
            ]);
            let handles = token.C_FindObjects(session, 2);
            assert.equal(handles.length, 2);
            handles = token.C_FindObjects(session, 2);
            assert.equal(handles.length, 1);
            token.C_FindObjectsFinal(session);
          });
        });
        context("Digest (SHA-256)", () => {
          it("C_DigestInit, C_Digest", () => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            const hash2 = token.C_Digest(session, data, hash);
            assert.equal(hash.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d0000000000000000");
            assert.equal(hash2.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
          });
          it("C_DigestInit, C_Digest async", (done) => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            token.C_Digest(session, data, hash, (error, hash2) => {
              if (error) {
                done(data);
              }
              else {
                assert.equal(hash2.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
                done();
              }
            });
          });
          it("C_DigestInit, C_DigestUpdate, C_DigestFinal", () => {
            const data = Buffer.from("message");
            const hash = Buffer.alloc(40);
            token.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256 });
            token.C_DigestUpdate(session, data);
            const hash2 = token.C_DigestFinal(session, hash);
            assert.equal(hash.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d0000000000000000");
            assert.equal(hash2.toString("hex"), "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d");
          });
        });
        // https://github.com/PeculiarVentures/pkcs11js/issues/47
        (os.platform() === "linux" && +/v(\d+)/.exec(process.version)[1] > 9
          ? context.skip
          : context)("Sign/Verify (RSA SHA-1, SHA-256)", () => {
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
              assert.equal(signature2.length < signature.length, true);
              assert.equal(signature2.toString("hex"), signature.slice(0, signature2.length).toString("hex"));
            });
            it("C_SignInit, C_Sign async", (done) => {
              const signature = Buffer.alloc(1024);
              token.C_SignInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.privateKey);
              token.C_Sign(session, data, signature, (error, signature2) => {
                if (error) {
                  done(error);
                }
                else {
                  assert.equal(signature2.length < signature.length, true);
                  done();
                }
              });
            });
            it("C_SignInit, C_SignUpdate, C_SignFinal", () => {
              const signature = Buffer.alloc(1024);
              token.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.privateKey);
              token.C_SignUpdate(session, data);
              const signature2 = token.C_SignFinal(session, signature);
              assert.equal(signature2.length < signature.length, true);
              assert.equal(signature2.toString("hex"), signature.slice(0, signature2.length).toString("hex"));
            });
            it("C_VerifyInit, C_Verify", () => {
              token.C_VerifyInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.publicKey);
              const ok = token.C_Verify(session, data, rsaPkcsSignature);
              assert.equal(ok, true);
            });
            it("C_VerifyInit, C_Verify async", (done) => {
              token.C_VerifyInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.publicKey);
              token.C_Verify(session, data, rsaPkcsSignature, (error, ok) => {
                if (error) {
                  done(error);
                }
                else {
                  assert.equal(ok, true);
                  done();
                }
              });
            });
            it("C_VerifyInit, C_VerifyUpdate, C_VerifyFinal", () => {
              token.C_VerifyInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.publicKey);
              token.C_VerifyUpdate(session, data);
              const ok = token.C_VerifyFinal(session, rsaPkcsSha256Signature);
              assert.equal(ok, true);
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
                  // sourceData: null, // SoftHSM v2.0.5 doesn't support sourceData parameter
                }
              };
              const data = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);
              token.C_EncryptInit(session, mechanism, keys.publicKey);
              const enc = token.C_Encrypt(session, data, Buffer.alloc(4098));

              token.C_DecryptInit(session, mechanism, keys.privateKey);
              const dec = token.C_Decrypt(session, enc, Buffer.alloc(1024));
              assert.equal(data.equals(dec), true);
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
          it("C_EncryptInit, C_Encrypt", () => {
            const enc = Buffer.alloc(1024);
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            const enc2 = token.C_Encrypt(session, data, enc);
            assert.equal(enc2.length < enc.length, true);
            assert.equal(enc2.toString("hex"), enc.slice(0, enc2.length).toString("hex"));
          });
          it("C_EncryptInit, C_Encrypt async", (done) => {
            const enc = Buffer.alloc(1024);
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            token.C_Encrypt(session, data, enc, (error, enc2) => {
              if (error) {
                done(error);
              }
              else {
                assert.equal(enc2.length < enc.length, true);
                done();
              }
            });
          });
          it("C_EncryptInit, C_EncryptUpdate, C_EncryptFinal", () => {
            token.C_EncryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            let enc = token.C_EncryptUpdate(session, data, Buffer.alloc(128));
            enc = Buffer.concat([enc, token.C_EncryptFinal(session, Buffer.alloc(128))]);
            assert.equal(enc.length > 0, true);
          });
          it("C_DecryptInit, C_Decrypt", () => {
            const dec = Buffer.alloc(1024);
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            const dec2 = token.C_Decrypt(session, encrypted, dec);
            assert.equal(dec2.length < dec.length, true);
            assert.equal(dec2.toString("hex"), dec.slice(0, dec2.length).toString("hex"));
          });
          it("C_DecryptInit, C_Decrypt async", (done) => {
            const dec = Buffer.alloc(1024);
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            token.C_Decrypt(session, encrypted, dec, (error, dec2) => {
              if (error) {
                done(error);
              }
              else {
                assert.equal(dec2.length < dec.length, true);
                done();
              }
            });
          });
          it("C_DecryptInit, C_DecryptUpdate, C_DecryptFinal", () => {
            token.C_DecryptInit(session, { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter }, key);
            let dec = token.C_DecryptUpdate(session, encrypted, Buffer.alloc(128));
            dec = Buffer.concat([dec, token.C_DecryptFinal(session, Buffer.alloc(128))]);
            assert.equal(dec.length > 0, true);
          });
        });
        (os.platform() === "linux" && +/v(\d+)/.exec(process.version)[1] > 9
          ? context.skip
          : context)("Derive (ECDH P-256)", () => {
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
              assert.equal(!!key, true);
            });
          });
      });
    });
  });
});
