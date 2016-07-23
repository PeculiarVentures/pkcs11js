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
### Example #2

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
