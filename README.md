# PKCS11js

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/graphene/master/LICENSE)

We make a package called [Graphene](https://github.com/PeculiarVentures/graphene), it provides a simplistic Object Oriented interface for interacting with PKCS#11 devices, for most people this is the right level to build on. In some cases you may want to interact directly with the PKCS#11 API, if so PKCS11js is the package for you.

PKCS#11 (also known as CryptoKI or PKCS11) is the standard interface for interacting with hardware crypto devices such as Smart Cards and Hardware Security Modules (HSMs). 

This was developed to the PKCS#11 2.3 specification, the 2.4 headers were not availible at the time we created this, it should be easy enough to extend it for the new version at a later date.

It has been tested with :
- [SoftHSM2](https://www.opendnssec.org/softhsm/)
- [Safenet Luna HSMs](http://www.safenet-inc.com/)
- [RuToken](http://www.rutoken.ru/)

**NOTE:** For testing purposes it may be easier to work with SoftHSM2 which is a software implementation of PKCS#11 based on OpenSSL or Botan.


## Installation

```
$ npm install pkcs11js
```

### Install SoftHSM2

SoftHSM2 is optional but as a software implementation of PKCS#11 it makes it easy to test the package. The bellow steps assume Ubuntu.

**Install SoftHSM2**

```
apt-get install softhsm
```
    
**Initialize the first slot**

```
softhsm2-util --init-token --slot 0 --label "My token 1"
```

The PKCS1 #11 module you can now use can be found here:

`/usr/local/lib/softhsm/libsofthsm.so`
  
**Adjust permissions so the user your code will be able to access the PKCS #11 module**

  ```
  sudo chmod –R 755 /var/lib/softhsm
  sudo chmod –R 755 /usr/local/lib/softhsm
  chown root:softhsmusers /var/lib/softhsm
  chown root:softhsmusers /usr/local/lib/softhsm
  ```
 
**NOTE**: This may be more generous than needed. It works out to : 0755 = User:rwx Group:r-x World:r-x. 
## Examples

### Example #1

```javascript
var pkcs11js = require("pkcs11js");

var pkcs11 = new pkcs11js.PKCS11();
pkcs11.load("/usr/local/lib/softhsm/libsofthsm2.so");

pkcs11.C_Initialize();

// Getting info about PKCS11 Module
var module_info = pkcs11.C_GetInfo();

// Getting list of slots
var slots = pkcs11.C_GetSlotList(true);
var slot = slots[0];

// Getting info about slot
var slot_info = pkcs11.C_GetSlotInfo(slot);
// Getting info about token
var token_info = pkcs11.C_GetTokenInfo(slot);

// Getting info about Mechanism
var mechs = pkcs11.C_GetMechanismList(slot);
var mech_info = pkcs11.C_GetMechanismInfo(slot, mechs[0]);

var session = pkcs11.C_OpenSession(slot, pkcs11.CKF_RW_SESSION | pkcs11.CKF_SERIAL_SESSION);

// Getting info about Session
var info = pkcs11.C_GetSessionInfo(session);
pkcs11.C_Login(session, 1, "password");

/**
 * Your app code here
 */

pkcs11.C_Logout(session);
pkcs11.C_CloseSession(session);
pkcs11.C_Finalize();
```

### Example #2

Generating secret key using AES mechanism

```javascript
var template = [
    { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
    { type: pkcs11.CKA_TOKEN, value: false },
    { type: pkcs11.CKA_LABEL, value: "My AES Key" },
    { type: pkcs11.CKA_VALUE_LEN, value: 256 / 8 },
    { type: pkcs11.CKA_ENCRYPT, value: true },
    { type: pkcs11.CKA_DECRYPT, value: true },
];
var key = pkcs11.C_GenerateKey(session, { mechanism: pkcs11.CKM_AES_KEY_GEN }, template);
```

### Example #3

Generating key pair using RSA-PKCS1 mechanism

```javascript
var publicKeyTemplate = [
    { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
    { type: pkcs11.CKA_TOKEN, value: false },
    { type: pkcs11.CKA_LABEL, value: "My RSA Public Key" },
    { type: pkcs11.CKA_PUBLIC_EXPONENT, value: new Buffer([1, 0, 1]) },
    { type: pkcs11.CKApkcs11ULUS_BITS, value: 2048 },
    { type: pkcs11.CKA_VERIFY, value: true }
];
var privateKeyTemplate = [
    { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
    { type: pkcs11.CKA_TOKEN, value: false },
    { type: pkcs11.CKA_LABEL, value: "My RSA Private Key" },
    { type: pkcs11.CKA_SIGN, value: true },
];
var keys = pkcs11.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN }, publicKeyTemplate, privateKeyTemplate);
```

### Example #4

Generating key pair using ECDSA mechanism

```javascript
var publicKeyTemplate = [
    { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
    { type: pkcs11.CKA_TOKEN, value: false },
    { type: pkcs11.CKA_LABEL, value: "My EC Public Key" },
    { type: pkcs11.CKA_EC_PARAMS, value: new Buffer("06082A8648CE3D030107", "hex") }, // secp256r1
];
var privateKeyTemplate = [
    { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
    { type: pkcs11.CKA_TOKEN, value: false },
    { type: pkcs11.CKA_LABEL, value: "My EC Private Key" },
    { type: pkcs11.CKA_DERIVE, value: true },
];
var keys = pkcs11.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_EC_KEY_PAIR_GEN }, publicKeyTemplate, privateKeyTemplate);
```

### Example #4

Working with Object

```javascript
var nObject = pkcs11.C_CreateObject(session, [
    { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_DATA },
    { type: pkcs11.CKA_TOKEN, value: false },
    { type: pkcs11.CKA_PRIVATE, value: false },
    { type: pkcs11.CKA_LABEL, value: "My custom data" },
]);

// Updating lable of Object
pkcs11.C_SetAttributeValue(session, nObject, [{ type: pkcs11.CKA_LABEL, value: nObjetcLabel + "!!!" }]);

// Getting attribute value
var label = pkcs11.C_GetAttributeValue(session, nObject, [
    { type: pkcs11.CKA_LABEL },
    { type: pkcs11.CKA_TOKEN }
]);
console.log(label[0].value.toString()); // My custom data!!!
console.log(!!label[1].value.readUInt8LE()); // false

// Copying Object
var cObject = pkcs11.C_CopyObject(session, nObject, [
    { type: pkcs11.CKA_CLASS},
    { type: pkcs11.CKA_TOKEN},
    { type: pkcs11.CKA_PRIVATE},
    { type: pkcs11.CKA_LABEL},
])

// Removing Object
pkcs11.C_DestroyObject(session, cObject);
```

## Suitability
At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.

## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. Graphene has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.

## Related
- [PKCS #11 2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html)
- [Many PKCS #11 Specifications](http://www.cryptsoft.com/pkcs11doc/)
- [PERL PKCS #11 binding](https://github.com/dotse/p5-crypt-pkcs11)
- [.NET PKCS #11 binding](https://github.com/jariq/Pkcs11Interop)
- [Ruby PKCS #11 binding](https://github.com/larskanis/pkcs11)
- [OCaml PKCS #11 binding](https://github.com/ANSSI-FR/caml-crush)
- [OCaml PKCS #11 CLI](https://github.com/ANSSI-FR/opkcs11-tool)
- [Go PKCS #11 binding](https://github.com/miekg/pkcs11) 
- [PKCS #11 Admin](http://www.pkcs11admin.net)
- [Node.js Foreign Function Interface](https://github.com/node-ffi/node-ffi)
- [GOST PKCS#11 constants](https://github.com/romanovskiy-k/pkcs11/blob/master/rtpkcs11t.h)
- [PKCS#11 logging proxy module](https://github.com/jariq/pkcs11-logger)
- [PKCS#11 Proxy](https://github.com/iksaif/pkcs11-proxy)
- [PKCS#11 Tests](https://github.com/google/pkcs11test)
- [OpenCryptoKi](http://sourceforge.net/projects/opencryptoki/)
- [SoftHSM](https://www.opendnssec.org/softhsm/)
- [SofHSM2 for Windows](https://github.com/disig/SoftHSM2-for-Windows/)
- [node-pcsc](https://github.com/santigimeno/node-pcsclite)
- [PKCS#11 URIs](https://tools.ietf.org/html/rfc7512)
- [Key Length Recommendations](http://www.keylength.com/en/compare/)
