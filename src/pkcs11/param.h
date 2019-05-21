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

class ParamBase {
public:
    const CK_ULONG type;
    
    ParamBase(CK_ULONG type) : type(type) { }
    virtual ~ParamBase() { }
    virtual void FromV8(Local<Value> v8Obj) {}
    virtual void* Get() = 0;
    virtual CK_ULONG GetSize() = 0;
protected:
};

template<typename T>
class Param : public ParamBase {
public:
    Param(CK_ULONG type) : ParamBase(type) { }
    void* Get() override { return &param; }
    virtual CK_ULONG GetSize() override { return sizeof(T); }
protected:
    T param;
};

#define CK_PARAMS_BUFFER            0
#define CK_PARAMS_AES_CBC		    1
#define CK_PARAMS_AES_CCM		    2
#define CK_PARAMS_AES_GCM		    3
#define CK_PARAMS_RSA_OAEP		    4
#define CK_PARAMS_RSA_PSS		    5
#define CK_PARAMS_EC_DH			    6
#define CK_PARAMS_AES_GCM_v240      7

class ParamBuffer : public ParamBase {
public:
    ParamBuffer() : ParamBase(CK_PARAMS_BUFFER) {}
    void* Get() { return param.data(); }
    virtual CK_ULONG GetSize() { return (CK_ULONG)param.size(); }
    void FromV8(Local<Value> v8Obj);
protected:
    std::vector<CK_BYTE> param;
};

// AES

class ParamAesCBC : public Param<CK_AES_CBC_ENCRYPT_DATA_PARAMS> {
public:
    ParamAesCBC() : Param(CK_PARAMS_AES_CBC) { Init(); }
    ~ParamAesCBC() { Free(); }
    void FromV8(Local<Value> v8Obj) override;
protected:
    void Init();
    void Free();
};

class ParamAesCCM : public Param<CK_AES_CCM_PARAMS> {
public:
    ParamAesCCM() : Param(CK_PARAMS_AES_CCM) { Init(); }
    ~ParamAesCCM() { Free(); }
    void FromV8(Local<Value> v8Obj) override;
protected:
    void Init();
    void Free();
};

class ParamAesGCM : public Param<CK_AES_GCM_PARAMS> {
public:
    ParamAesGCM() : Param(CK_PARAMS_AES_GCM) { Init(); }
    ~ParamAesGCM() { Free(); }
    void FromV8(Local<Value> v8Obj) override;
protected:
    void Init();
    void Free();
};


class ParamAesGCMv240 : public Param<CK_AES_GCM_240_PARAMS> {
public:
    ParamAesGCMv240() : Param(CK_PARAMS_AES_GCM_v240) { Init(); }
    ~ParamAesGCMv240() { Free(); }
    void FromV8(Local<Value> v8Obj) override;
protected:
    void Init();
    void Free();
};

// RSA

class ParamRsaOAEP : public Param<CK_RSA_PKCS_OAEP_PARAMS> {
public:
    ParamRsaOAEP() : Param(CK_PARAMS_RSA_OAEP) { Init(); }
    ~ParamRsaOAEP() { Free(); }
    void FromV8(Local<Value> v8Obj) override;
protected:
    void Init();
    void Free();
};

class ParamRsaPSS : public Param<CK_RSA_PKCS_PSS_PARAMS> {
public:
    ParamRsaPSS() : Param(CK_PARAMS_RSA_PSS) { Init(); }
    ~ParamRsaPSS() { Free(); }
    void FromV8(Local<Value> v8Obj) override;
protected:
    void Init();
    void Free();
};

// ECC

class ParamEcdh1 : public Param<CK_ECDH1_DERIVE_PARAMS> {
public:
    ParamEcdh1() : Param(CK_PARAMS_EC_DH) { Init(); }
    ~ParamEcdh1() { Free(); }
    void FromV8(Local<Value> v8Obj) override;
protected:
    void Init();
    void Free();
};

#endif // INCLUDE_H_PKCS11_PARAM
