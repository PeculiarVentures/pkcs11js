#ifndef INCLUDE_H_PKCS11_PARAM_ECDH1
#define INCLUDE_H_PKCS11_PARAM_ECDH1

#include "core.h"
#include "v8_convert.h"

class ParamEcdh1 : public V8Converter<CK_ECDH1_DERIVE_PARAMS> {
public:
	ParamEcdh1();
	~ParamEcdh1();
	void FromV8(Local<Value> obj);
	// Local<Object> ToV8();
	CK_ECDH1_DERIVE_PARAMS_PTR New();
	void Free();
};

#endif // INCLUDE_H_PKCS11_PARAM_ECDH1