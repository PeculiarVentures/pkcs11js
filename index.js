/*!
 * Copyright (c) 2020 Peculiar Ventures, LLC
 */

const pkcs11 = require("./build/Release/pkcs11.node");
const util = require("node:util");

// pkcs11.PKCS11.prototype.C_EncryptAsync = util.promisify(pkcs11.PKCS11.prototype.C_Encrypt);
// pkcs11.PKCS11.prototype.C_DecryptAsync = util.promisify(pkcs11.PKCS11.prototype.C_Decrypt);
// pkcs11.PKCS11.prototype.C_DigestAsync = util.promisify(pkcs11.PKCS11.prototype.C_Digest);
// pkcs11.PKCS11.prototype.C_SignAsync = util.promisify(pkcs11.PKCS11.prototype.C_Sign);
// pkcs11.PKCS11.prototype.C_VerifyAsync = util.promisify(pkcs11.PKCS11.prototype.C_Verify);
// pkcs11.PKCS11.prototype.C_GenerateKeyAsync = util.promisify(pkcs11.PKCS11.prototype.C_GenerateKey);
// pkcs11.PKCS11.prototype.C_GenerateKeyPairAsync = util.promisify(pkcs11.PKCS11.prototype.C_GenerateKeyPair);
// pkcs11.PKCS11.prototype.C_WrapKeyAsync = util.promisify(pkcs11.PKCS11.prototype.C_WrapKey);
// pkcs11.PKCS11.prototype.C_UnwrapKeyAsync = util.promisify(pkcs11.PKCS11.prototype.C_UnwrapKey);
// pkcs11.PKCS11.prototype.C_DeriveKeyAsync = util.promisify(pkcs11.PKCS11.prototype.C_DeriveKey);

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

function modifyMethodWithSubarray(methodName, argIndex, prototype) {
  const old = prototype[methodName];
  prototype[methodName] = function (...args) {
    const res = old.apply(this, args);
    return args[argIndex].subarray(0, res);
  };
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

function fixCallbackArgs(cb, dataToSubarray) {
  if (typeof cb === "function") {
    return function (err, data) {
      if (err) {
        return cb(prepareError(err), null);
      }
      cb(null, dataToSubarray.subarray(0, data));
    };
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
      case "C_Digest": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 4) {
            // sync
            const res = old.apply(this, args);
            return args[2].subarray(0, res);
          } else {
            // callback
            return this.C_DigestCallback(...args);
          }
        };
        break;
      }
      case "C_DigestCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[3];
          if (typeof oldCallback === "function") {
            args[3] = fixCallbackArgs(oldCallback, args[2]);
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_DigestFinal": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 3) {
            // sync
            const res = old.apply(this, args);
            return args[1].subarray(0, res);
          } else {
            // callback
            return this.C_DigestFinalCallback(...args);
          }
        };
        break;
      }
      case "C_DigestFinalCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[2];
          if (typeof oldCallback === "function") {
            args[2] = fixCallbackArgs(oldCallback, args[1]);
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_Sign": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 4) {
            // sync
            const res = old.apply(this, args);
            return args[2].subarray(0, res);
          } else {
            // callback
            return this.C_SignCallback(...args);
          }
        };
        break;
      }
      case "C_SignCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[3];
          if (typeof oldCallback === "function") {
            args[3] = fixCallbackArgs(oldCallback, args[2]);
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_SignFinal": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 3) {
            // sync
            const res = old.apply(this, args);
            return args[1].subarray(0, res);
          } else {
            // callback
            return this.C_SignFinalCallback(...args);
          }
        };
        break;
      }
      case "C_SignFinalCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[2];
          if (typeof oldCallback === "function") {
            args[2] = fixCallbackArgs(oldCallback, args[1]);
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_Encrypt": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 4) {
            // sync
            const res = old.apply(this, args);
            return args[2].subarray(0, res);
          } else {
            // callback
            return this.C_EncryptCallback(...args);
          }
        };
        break;
      }
      case "C_EncryptCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[3];
          if (typeof oldCallback === "function") {
            args[3] = fixCallbackArgs(oldCallback, args[2]);
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
      }
      case "C_EncryptUpdate": {
        modifyMethodWithSubarray(key, 2, pkcs11.PKCS11.prototype);
        break;
      }
      case "C_EncryptFinal": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 3) {
            // sync
            const res = old.apply(this, args);
            return args[1].subarray(0, res);
          } else {
            // callback
            return this.C_EncryptFinalCallback(...args);
          }
        };
        break;
      }
      case "C_EncryptFinalCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[2];
          if (typeof oldCallback === "function") {
            args[2] = fixCallbackArgs(oldCallback, args[1]);
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_Decrypt": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 4) {
            // sync
            const res = old.apply(this, args);
            return args[2].subarray(0, res);
          } else {
            // callback
            return this.C_DecryptCallback(...args);
          }
        };
        break;
      }
      case "C_DecryptCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[3];
          if (typeof oldCallback === "function") {
            args[3] = fixCallbackArgs(oldCallback, args[2]);
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
      }
      case "C_DecryptUpdate": {
        modifyMethodWithSubarray(key, 2, pkcs11.PKCS11.prototype);
        break;
      }
      case "C_DecryptFinal": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 3) {
            // sync
            const res = old.apply(this, args);
            return args[1].subarray(0, res);
          } else {
            // callback
            return this.C_DecryptFinalCallback(...args);
          }
        };
        break;
      }
      case "C_DecryptFinalCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[2];
          if (typeof oldCallback === "function") {
            args[2] = fixCallbackArgs(oldCallback, args[1]);
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_Verify": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 4) {
            // sync
            return old.apply(this, args);
          } else {
            // callback
            return this.C_VerifyCallback(...args);
          }
        };
        break;
      }
      case "C_VerifyCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[3];
          if (typeof oldCallback === "function") {
            args[3] = (err, res) => {
              if (err) {
                return oldCallback(prepareError(err), null);
              }
              oldCallback(null, res);
            };
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_VerifyFinal": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 3) {
            // sync
            return old.apply(this, args);
          } else {
            // callback
            return this.C_VerifyFinalCallback(...args);
          }
        };
        break;
      }
      case "C_VerifyFinalCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[2];
          if (typeof oldCallback === "function") {
            args[2] = (err, res) => {
              if (err) {
                return oldCallback(prepareError(err), null);
              }
              oldCallback(null, res);
            };
          }
          return old.apply(this, args);
        };
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_GenerateKey": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 4) {
            // sync
            return old.apply(this, args);
          }
          // callback
          return this.C_GenerateKeyCallback(...args);
        }
        break;
      }
      case "C_GenerateKeyCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[3];
          if (typeof oldCallback === "function") {
            args[3] = (err, res) => {
              if (err) {
                return oldCallback(prepareError(err), null);
              }
              oldCallback(null, res);
            };
          }
          return old.apply(this, args);
        }
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_GenerateKeyPair": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 5) {
            // sync
            return old.apply(this, args);
          }
          // callback
          return this.C_GenerateKeyPairCallback(...args);
        }
        break;
      }
      case "C_GenerateKeyPairCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[4];
          if (typeof oldCallback === "function") {
            args[4] = (err, res) => {
              if (err) {
                return oldCallback(prepareError(err), null);
              }
              oldCallback(null, res);
            };
          }
          return old.apply(this, args);
        }
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_DeriveKey": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 5) {
            // sync
            return old.apply(this, args);
          }
          // callback
          return this.C_DeriveKeyCallback(...args);
        }
        break;
      }
      case "C_DeriveKeyCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[5];
          if (typeof oldCallback === "function") {
            args[5] = (err, res) => {
              if (err) {
                return oldCallback(prepareError(err), null);
              }
              oldCallback(null, res);
            };
          }
          return old.apply(this, args);
        }
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_WrapKey": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 6) {
            // sync
            const res = old.apply(this, args);
            return args[4].subarray(0, res);
          }
          // callback
          return this.C_WrapKeyCallback(...args);
        }
        break;
      }
      case "C_WrapKeyCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {

          const oldCallback = args[4];
          if (typeof oldCallback === "function") {
            args[4] = (err, res) => {
              if (err) {
                return oldCallback(prepareError(err), null);
              }
              oldCallback(null, res);
            };
          }
          return old.apply(this, args);
        }
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);
        break;
      }
      case "C_UnwrapKey": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          if (args.length < 6) {
            // sync
            return old.apply(this, args);
          }
          // callback
          return this.C_UnwrapKeyCallback(...args);
        }
        break;
      }
      case "C_UnwrapKeyCallback": {
        const old = pkcs11.PKCS11.prototype[key];
        pkcs11.PKCS11.prototype[key] = function (...args) {
          const oldCallback = args[5];
          if (typeof oldCallback === "function") {
            args[5] = (err, res) => {
              if (err) {
                return oldCallback(prepareError(err), null);
              }
              oldCallback(null, res);
            };
          }
          return old.apply(this, args);
        }
        // async
        const name = key.replace("Callback", "Async");
        pkcs11.PKCS11.prototype[name] = util.promisify(pkcs11.PKCS11.prototype[key]);

        break;
      }
      case "C_SignRecover": {
        modifyMethodWithSubarray(key, 2, pkcs11.PKCS11.prototype);
        break;
      }
      case "C_VerifyRecover": {
        modifyMethodWithSubarray(key, 2, pkcs11.PKCS11.prototype);
        break;
      }
    }
  }
}


module.exports = pkcs11