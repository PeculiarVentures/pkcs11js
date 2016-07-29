#ifndef INCLUDE_H_PKCS11_PARAM
#define INCLUDE_H_PKCS11_PARAM

#include "core.h"
#include "v8_convert.h"

// HELPERS

#define DECLARE_CHECK_PARAM(name) bool check_param_##name(Local<Object> obj, const char* paramName)

DECLARE_CHECK_PARAM(buffer);
DECLARE_CHECK_PARAM(number);
DECLARE_CHECK_PARAM(empty);

#undef DECLARE_CHECK_PARAM

#define DECLARE_PARAM_CLASS(name, CK_TYPE)											\
class Param##name : public V8Converter<CK_TYPE> {									\
public:																				\
	Param##name() { New(); }														\
	~Param##name() { Free(); }														\
	void FromV8(Local<Value> obj);													\
	CK_TYPE##_PTR New();															\
	void Free();																	\
}

DECLARE_PARAM_CLASS(AesCBC, CK_AES_CBC_ENCRYPT_DATA_PARAMS);
DECLARE_PARAM_CLASS(AesCCM, CK_AES_CCM_PARAMS);
DECLARE_PARAM_CLASS(AesGCM, CK_AES_GCM_PARAMS);
DECLARE_PARAM_CLASS(RsaOAEP, CK_RSA_PKCS_OAEP_PARAMS);
DECLARE_PARAM_CLASS(RsaPSS, CK_RSA_PKCS_PSS_PARAMS);
DECLARE_PARAM_CLASS(Ecdh1, CK_ECDH1_DERIVE_PARAMS);

#undef DECLARE_PARAM_CLASS

#endif // INCLUDE_H_PKCS11_PARAM