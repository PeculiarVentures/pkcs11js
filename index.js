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

module.exports = pkcs11