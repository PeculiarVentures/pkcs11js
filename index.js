/*!
 * Copyright (c) 2020 Peculiar Ventures, LLC
 */

const pkcs11 = require("./build/Release/pkcs11.node");
const util = require("node:util");

class NativeError extends Error {
  constructor(message, method) {
    super(message || "");

    this.name = NativeError.name;
    this.method = method || "";
    this.nativeStack = "";

    const messages = this.message.split("\n");
    const matches = /(\w+):(\d+)/.exec(this.message);
    if (matches) {
      this.message = matches[1];
      this.code = +matches[2];
      if (messages.length > 1) {
        //     at PKCS11.C_Finalize (/Users/microshine/g
        const stackMatch = /at PKCS11\.(\w+) \(/.exec(messages[1]);
        if (stackMatch) {
          this.method = stackMatch[1];
        }
        this.nativeStack = messages.slice(1).join("\n");
      }
    } else {
      this.message = messages[0];
      this.code = 0;
    }
  }
}

pkcs11.NativeError = NativeError;

class Pkcs11Error extends NativeError {
  constructor(message, code, method) {
    super(message, method);

    this.name = Pkcs11Error.name;
    this.code = code || 0;

    const matches = new RegExp(Pkcs11Error.messageReg).exec(message);
    if (matches) {
      this.message = matches[1];
      this.code = +matches[2];
    }
  }
}

Pkcs11Error.messageReg = /(CKR_[^:]+):(\d+)/;

Pkcs11Error.isPkcs11 = function isPkcs11(message) {
  return new RegExp(Pkcs11Error.messageReg).test(message);
}

pkcs11.Pkcs11Error = Pkcs11Error;

function prepareError(e) {
  if (Pkcs11Error.isPkcs11(e.stack)) {
    return new Pkcs11Error(e.stack);
  }
  if (e instanceof TypeError) {
    return e;
  }
  return new NativeError(e.message);
}

function handleError(e) {
  throw prepareError(e);
}

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
          handleError(e);
        });
      }
      return res;
    } catch (e) {
      handleError(e);
    }
  };
}

function modifyCallback(cb, data, useSubarray) {
  if (typeof cb === "function") {
    return function (err, dataOrLength) {
      if (err) {
        return cb(prepareError(err), null);
      }
      if (useSubarray) {
        // Call the callback with subarray
        cb(null, data.subarray(0, dataOrLength));
      } else {
        // Call the original callback
        cb(null, dataOrLength);
      }
    };
  }
}

function modifyMethod(key, prototype, config) {
  const oldMethod = prototype[key];
  const callbackMethodName = key + "Callback";

  // Modified method
  prototype[key] = function (...args) {
    // Handle callback logic if callbackIndex is defined
    if (config.callbackIndex !== undefined && args.length > config.callbackIndex) {
      return this[callbackMethodName].apply(this, args);
    }

    // Execute the original method
    const result = oldMethod.apply(this, args);

    // If outputIndex is defined, modify the output
    if (config.outputIndex !== undefined) {
      return args[config.outputIndex].subarray(0, result);
    }

    // Return the original result if outputIndex is not defined
    return result;
  };

  // If callbackIndex is defined, update the callback method and promisify it
  if (config.callbackIndex !== undefined) {
    const oldCallbackMethod = prototype[callbackMethodName];

    prototype[callbackMethodName] = function (...args) {
      if (typeof args[config.callbackIndex] === "function") {
        args[config.callbackIndex] = modifyCallback(args[config.callbackIndex], args[config.outputIndex], config.outputIndex !== undefined);
      }
      return oldCallbackMethod.apply(this, args);
    };

    // Promisify the callback method
    const asyncMethodName = key + "Async";
    prototype[asyncMethodName] = util.promisify(prototype[callbackMethodName]);
  }
}


// Customize native exceptions
for (const key in pkcs11.PKCS11.prototype) {
  if (pkcs11.PKCS11.prototype.hasOwnProperty(key)) {
    pkcs11.PKCS11.prototype[key] = catchError(pkcs11.PKCS11.prototype[key]);

    switch (key) {
      case "C_FindObjects": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 2) {
            args.push(1);
            return old.apply(this, args)[0] || null;
          }
          return old.apply(this, args);
        };
        break;
      }
      case "C_Digest":
      case "C_Sign":
      case "C_Encrypt":
      case "C_Decrypt":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            outputIndex: 2,
            callbackIndex: 3,
          });
          break;
        }
      case "C_DigestFinal":
      case "C_SignFinal":
      case "C_EncryptFinal":
      case "C_DecryptFinal":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            outputIndex: 1,
            callbackIndex: 2,
          });
          break;
        }
      case "C_DecryptUpdate":
      case "C_EncryptUpdate":
      case "C_SignRecover":
      case "C_VerifyRecover":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            outputIndex: 2,
          });
          break;
        }
      case "C_Verify":
      case "C_GenerateKey":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            callbackIndex: 3,
          });
          break;
        }
      case "C_VerifyFinal":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            callbackIndex: 2,
          });
          break;
        }
      case "C_GenerateKeyPair":
      case "C_DeriveKey":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            callbackIndex: 4,
          });
          break;
        }
      case "C_WrapKey":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            outputIndex: 4,
            callbackIndex: 5,
          });
          break;
        }
      case "C_UnwrapKey":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            callbackIndex: 5,
          });
          break;
        }
      case "C_DigestEncryptUpdate":
      case "C_DecryptDigestUpdate":
      case "C_SignEncryptUpdate":
      case "C_DecryptVerifyUpdate":
        {
          modifyMethod(key, pkcs11.PKCS11.prototype, {
            outputIndex: 2,
            callbackIndex: 3,
          });
          break;
        }
    }
  }
}

module.exports = pkcs11
