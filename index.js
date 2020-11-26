/*!
 * Copyright (c) 2020 Peculiar Ventures, LLC
 */

const pkcs11 = require("./build/Release/pkcs11.node");
const util = require("util");

pkcs11.PKCS11.prototype.C_EncryptAsync = util.promisify(pkcs11.PKCS11.prototype.C_Encrypt);
pkcs11.PKCS11.prototype.C_DecryptAsync = util.promisify(pkcs11.PKCS11.prototype.C_Decrypt);
pkcs11.PKCS11.prototype.C_DigestAsync = util.promisify(pkcs11.PKCS11.prototype.C_Digest);
pkcs11.PKCS11.prototype.C_SignAsync = util.promisify(pkcs11.PKCS11.prototype.C_Sign);
pkcs11.PKCS11.prototype.C_VerifyAsync = util.promisify(pkcs11.PKCS11.prototype.C_Verify);
pkcs11.PKCS11.prototype.C_GenerateKeyAsync = util.promisify(pkcs11.PKCS11.prototype.C_GenerateKey);
pkcs11.PKCS11.prototype.C_GenerateKeyPairAsync = util.promisify(pkcs11.PKCS11.prototype.C_GenerateKeyPair);
pkcs11.PKCS11.prototype.C_WrapKeyAsync = util.promisify(pkcs11.PKCS11.prototype.C_WrapKey);
pkcs11.PKCS11.prototype.C_UnwrapKeyAsync = util.promisify(pkcs11.PKCS11.prototype.C_UnwrapKey);
pkcs11.PKCS11.prototype.C_DeriveKeyAsync = util.promisify(pkcs11.PKCS11.prototype.C_DeriveKey);

function NativeError(message, method) {
  this.name = NativeError.name;
  this.message = message || "";
  this.method = method || "";
  this.nativeStack = "";

  const messages = this.message.split("\n");
  this.message = messages[0];
  if (messages.length > 1) {
    this.nativeStack = messages.slice(1).join("\n");

    const matches = /(\w+):\d+/.exec(this.nativeStack);
    if (matches) {
      this.method = matches[1];
    }
  }
}
util.inherits(NativeError, Error);

pkcs11.NativeError = NativeError;

function Pkcs11Error(message, code, method) {
  NativeError.call(this, message, method);

  this.name = Pkcs11Error.name;
  this.code = code || 0;

  const matches = new RegExp(Pkcs11Error.messageReg).exec(message);
  if (matches) {
    this.message = matches[1];
    this.code = +matches[2];
  }
}
util.inherits(Pkcs11Error, NativeError);

Pkcs11Error.messageReg = /(CKR_[^:]+):(\d+)/;

Pkcs11Error.isPkcs11 = function isPkcs11(message) {
  return new RegExp(Pkcs11Error.messageReg).test(message);
}

pkcs11.Pkcs11Error = Pkcs11Error;

/**
 * Catches and wraps PKCS#11 errors to Pkcs11Error
 * @param {*} fn 
 */
function catchError(fn) {
  return function (...args) {
    try {
      const res = fn.apply(this, args);
      if (res instanceof Promise) {
        return res.catch((e) => {
          if (Pkcs11Error.isPkcs11(e.message)) {
            throw new Pkcs11Error(e.message);
          }
          throw new NativeError(e.message);
        });
      }
      return res;
    } catch (e) {
      if (Pkcs11Error.isPkcs11(e.message)) {
        throw new Pkcs11Error(e.message);
      }
      throw new NativeError(e.message);
    }
  };
}

// Customize native exceptions
for (const key in pkcs11.PKCS11.prototype) {
  if (pkcs11.PKCS11.prototype.hasOwnProperty(key)) {
    pkcs11.PKCS11.prototype[key] = catchError(pkcs11.PKCS11.prototype[key]);
  }
}


module.exports = pkcs11