#include <node.h>
#include <node_buffer.h>

#ifdef WIN32
#include "dl.h"
#else
#include <dlfcn.h>
#endif // WIN32


#include "const.h"
#include "pkcs11.h"

#define UNWRAP_PKCS11 PKCS11 *__pkcs11= PKCS11::Unwrap<PKCS11>(info.This())

#define SET_PKCS11_METHOD(name) SetPrototypeMethod(tpl, #name, name)

#define CASE_PKCS11_ERROR(_value) 					\
	case _value:									\
		return #_value

static char* get_pkcs11_error(CK_ULONG value) {
	switch (value) {
		CASE_PKCS11_ERROR(CKR_OK);
		CASE_PKCS11_ERROR(CKR_CANCEL);
		CASE_PKCS11_ERROR(CKR_HOST_MEMORY);
		CASE_PKCS11_ERROR(CKR_SLOT_ID_INVALID);
		CASE_PKCS11_ERROR(CKR_GENERAL_ERROR);
		CASE_PKCS11_ERROR(CKR_FUNCTION_FAILED);
		CASE_PKCS11_ERROR(CKR_ARGUMENTS_BAD);
		CASE_PKCS11_ERROR(CKR_NO_EVENT);
		CASE_PKCS11_ERROR(CKR_NEED_TO_CREATE_THREADS);
		CASE_PKCS11_ERROR(CKR_CANT_LOCK);
		CASE_PKCS11_ERROR(CKR_ATTRIBUTE_READ_ONLY);
		CASE_PKCS11_ERROR(CKR_ATTRIBUTE_SENSITIVE);
		CASE_PKCS11_ERROR(CKR_ATTRIBUTE_TYPE_INVALID);
		CASE_PKCS11_ERROR(CKR_ATTRIBUTE_VALUE_INVALID);
		CASE_PKCS11_ERROR(CKR_DATA_INVALID);
		CASE_PKCS11_ERROR(CKR_DATA_LEN_RANGE);
		CASE_PKCS11_ERROR(CKR_DEVICE_ERROR);
		CASE_PKCS11_ERROR(CKR_DEVICE_MEMORY);
		CASE_PKCS11_ERROR(CKR_DEVICE_REMOVED);
		CASE_PKCS11_ERROR(CKR_ENCRYPTED_DATA_INVALID);
		CASE_PKCS11_ERROR(CKR_ENCRYPTED_DATA_LEN_RANGE);
		CASE_PKCS11_ERROR(CKR_FUNCTION_CANCELED);
		CASE_PKCS11_ERROR(CKR_FUNCTION_NOT_PARALLEL);
		CASE_PKCS11_ERROR(CKR_FUNCTION_NOT_SUPPORTED);
		CASE_PKCS11_ERROR(CKR_KEY_HANDLE_INVALID);
		CASE_PKCS11_ERROR(CKR_KEY_SIZE_RANGE);
		CASE_PKCS11_ERROR(CKR_KEY_TYPE_INCONSISTENT);
		CASE_PKCS11_ERROR(CKR_KEY_NOT_NEEDED);
		CASE_PKCS11_ERROR(CKR_KEY_CHANGED);
		CASE_PKCS11_ERROR(CKR_KEY_NEEDED);
		CASE_PKCS11_ERROR(CKR_KEY_INDIGESTIBLE);
		CASE_PKCS11_ERROR(CKR_KEY_FUNCTION_NOT_PERMITTED);
		CASE_PKCS11_ERROR(CKR_KEY_NOT_WRAPPABLE);
		CASE_PKCS11_ERROR(CKR_KEY_UNEXTRACTABLE);
		CASE_PKCS11_ERROR(CKR_MECHANISM_INVALID);
		CASE_PKCS11_ERROR(CKR_MECHANISM_PARAM_INVALID);
		CASE_PKCS11_ERROR(CKR_OBJECT_HANDLE_INVALID);
		CASE_PKCS11_ERROR(CKR_OPERATION_ACTIVE);
		CASE_PKCS11_ERROR(CKR_OPERATION_NOT_INITIALIZED);
		CASE_PKCS11_ERROR(CKR_PIN_INCORRECT);
		CASE_PKCS11_ERROR(CKR_PIN_INVALID);
		CASE_PKCS11_ERROR(CKR_PIN_LEN_RANGE);
		CASE_PKCS11_ERROR(CKR_PIN_EXPIRED);
		CASE_PKCS11_ERROR(CKR_PIN_LOCKED);
		CASE_PKCS11_ERROR(CKR_SESSION_CLOSED);
		CASE_PKCS11_ERROR(CKR_SESSION_COUNT);
		CASE_PKCS11_ERROR(CKR_SESSION_HANDLE_INVALID);
		CASE_PKCS11_ERROR(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
		CASE_PKCS11_ERROR(CKR_SESSION_READ_ONLY);
		CASE_PKCS11_ERROR(CKR_SESSION_EXISTS);
		CASE_PKCS11_ERROR(CKR_SESSION_READ_ONLY_EXISTS);
		CASE_PKCS11_ERROR(CKR_SESSION_READ_WRITE_SO_EXISTS);
		CASE_PKCS11_ERROR(CKR_SIGNATURE_INVALID);
		CASE_PKCS11_ERROR(CKR_SIGNATURE_LEN_RANGE);
		CASE_PKCS11_ERROR(CKR_TEMPLATE_INCOMPLETE);
		CASE_PKCS11_ERROR(CKR_TEMPLATE_INCONSISTENT);
		CASE_PKCS11_ERROR(CKR_TOKEN_NOT_PRESENT);
		CASE_PKCS11_ERROR(CKR_TOKEN_NOT_RECOGNIZED);
		CASE_PKCS11_ERROR(CKR_TOKEN_WRITE_PROTECTED);
		CASE_PKCS11_ERROR(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
		CASE_PKCS11_ERROR(CKR_UNWRAPPING_KEY_SIZE_RANGE);
		CASE_PKCS11_ERROR(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
		CASE_PKCS11_ERROR(CKR_USER_ALREADY_LOGGED_IN);
		CASE_PKCS11_ERROR(CKR_USER_NOT_LOGGED_IN);
		CASE_PKCS11_ERROR(CKR_USER_PIN_NOT_INITIALIZED);
		CASE_PKCS11_ERROR(CKR_USER_TYPE_INVALID);
		CASE_PKCS11_ERROR(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
		CASE_PKCS11_ERROR(CKR_USER_TOO_MANY_TYPES);
		CASE_PKCS11_ERROR(CKR_WRAPPED_KEY_INVALID);
		CASE_PKCS11_ERROR(CKR_WRAPPED_KEY_LEN_RANGE);
		CASE_PKCS11_ERROR(CKR_WRAPPING_KEY_HANDLE_INVALID);
		CASE_PKCS11_ERROR(CKR_WRAPPING_KEY_SIZE_RANGE);
		CASE_PKCS11_ERROR(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
		CASE_PKCS11_ERROR(CKR_RANDOM_SEED_NOT_SUPPORTED);
		CASE_PKCS11_ERROR(CKR_RANDOM_NO_RNG);
		CASE_PKCS11_ERROR(CKR_DOMAIN_PARAMS_INVALID);
		CASE_PKCS11_ERROR(CKR_BUFFER_TOO_SMALL);
		CASE_PKCS11_ERROR(CKR_SAVED_STATE_INVALID);
		CASE_PKCS11_ERROR(CKR_INFORMATION_SENSITIVE);
		CASE_PKCS11_ERROR(CKR_STATE_UNSAVEABLE);
		CASE_PKCS11_ERROR(CKR_CRYPTOKI_NOT_INITIALIZED);
		CASE_PKCS11_ERROR(CKR_CRYPTOKI_ALREADY_INITIALIZED);
		CASE_PKCS11_ERROR(CKR_MUTEX_BAD);
		CASE_PKCS11_ERROR(CKR_MUTEX_NOT_LOCKED);
		CASE_PKCS11_ERROR(CKR_NEW_PIN_MODE);
		CASE_PKCS11_ERROR(CKR_NEXT_OTP);
		CASE_PKCS11_ERROR(CKR_EXCEEDED_MAX_ITERATIONS);
		CASE_PKCS11_ERROR(CKR_FIPS_SELF_TEST_FAILED);
		CASE_PKCS11_ERROR(CKR_LIBRARY_LOAD_FAILED);
		CASE_PKCS11_ERROR(CKR_PIN_TOO_WEAK);
		CASE_PKCS11_ERROR(CKR_PUBLIC_KEY_INVALID);
		CASE_PKCS11_ERROR(CKR_FUNCTION_REJECTED);
		CASE_PKCS11_ERROR(CKR_VENDOR_DEFINED);
	default:
		return "Unknown error";
	}
}

#define THROW_PKCS11_ERROR(code) \
	Local<String> v8ErrorMessage = String::Concat(Nan::New(__FUNCTION__).ToLocalChecked(), Nan::New(" #").ToLocalChecked()); \
	v8ErrorMessage = String::Concat(v8ErrorMessage, Nan::New<Number>((int)code)->ToString()); \
	v8ErrorMessage = String::Concat(v8ErrorMessage, Nan::New(": ").ToLocalChecked()); \
	v8ErrorMessage = String::Concat(v8ErrorMessage, Nan::New(get_pkcs11_error(code)).ToLocalChecked()); \
	Nan::ThrowError(v8ErrorMessage);

#define THROW_V8_ERROR(text)	\
	{Nan::ThrowError(text);		\
	return;}

#define THROW_V8_TYPE_ERROR(text)	\
	{Nan::ThrowTypeError(text);		\
	return;}

#define THROW_REQUIRED(argsIndex)	\
	{Local<String> v8ErrorMessage = String::Concat(Nan::New("Parameter ").ToLocalChecked(), Nan::New<Number>(argsIndex+1)->ToString()); \
	v8ErrorMessage = String::Concat(v8ErrorMessage, Nan::New(" is REQUIRED").ToLocalChecked()); \
	THROW_V8_TYPE_ERROR(v8ErrorMessage)}

#define CHECK_REQUIRED(argsIndex)								\
	if (info[argsIndex]->IsUndefined() /*|| info[argsIndex]->IsNull()*/)	\
		THROW_REQUIRED(argsIndex)

#define THROW_WRONG_TYPE(argsIndex, v8Type)	\
	{Local<String> v8ErrorMessage = String::Concat(Nan::New("Parameter ").ToLocalChecked(), Nan::New<Number>(argsIndex+1)->ToString()); \
	v8ErrorMessage = String::Concat(v8ErrorMessage, Nan::New(" MUST be ").ToLocalChecked()); \
	v8ErrorMessage = String::Concat(v8ErrorMessage, Nan::New(#v8Type).ToLocalChecked()); \
	THROW_V8_TYPE_ERROR(v8ErrorMessage)}


#define CHECK_TYPE(argsIndex, v8Type)										\
	if (!info[argsIndex]->Is##v8Type())										\
		THROW_WRONG_TYPE(argsIndex, v8Type)

#define CHECK_PKCS11_RV(func)   \
{   CK_RV rv = func;            \
    if (rv != CKR_OK) {         \
		THROW_PKCS11_ERROR(rv); \
		return;                 \
    }                           \
}

#define GET_BUFFER(varName, v8Object)									\
	char* varName = node::Buffer::Data(v8Object);						\
	CK_ULONG varName##Len = (CK_ULONG)node::Buffer::Length(v8Object);

#define GET_BUFFER_ARGS(varName, argIndex)								\
	GET_BUFFER(varName, info[argIndex]);					

typedef CK_ECDH1_DERIVE_PARAMS ECDH1_DERIVE_PARAMS;

ECDH1_DERIVE_PARAMS* ECDH1_DERIVE_PARAMS_new() {
	ECDH1_DERIVE_PARAMS* res = (ECDH1_DERIVE_PARAMS*)malloc(sizeof(ECDH1_DERIVE_PARAMS));
	res->ulSharedDataLen = 0;
	res->pSharedData = NULL_PTR;
	res->ulPublicDataLen = 0;
	res->pPublicData = NULL_PTR;
	return res;
}

void ECDH1_DERIVE_PARAMS_free(ECDH1_DERIVE_PARAMS* params) {
	if (params) {
		if (params->pSharedData)
			free(params->pSharedData);
		if (params->pPublicData)
			free(params->pPublicData);
		free(params);
	}
}

static ECDH1_DERIVE_PARAMS* v2c_ECDH1_DERIVE_PARAMS(Local<Object> v8Params) {
	Nan::HandleScope();

	if (!v8Params->Get(Nan::New(STR_KDF).ToLocalChecked())->IsNumber())
		return NULL;
	if (!(v8Params->Get(Nan::New(STR_SHARED_DATA).ToLocalChecked())->IsUndefined()
		|| Buffer::HasInstance(v8Params->Get(Nan::New(STR_SHARED_DATA).ToLocalChecked())->ToObject())))
		return NULL;
	if (!Buffer::HasInstance(v8Params->Get(Nan::New(STR_PUBLIC_DATA).ToLocalChecked())->ToObject()))
		return NULL;

	puts("ECDH1 params: OK");

	ECDH1_DERIVE_PARAMS* params = ECDH1_DERIVE_PARAMS_new();

	params->kdf = (CK_ULONG)v8Params->Get(Nan::New(STR_KDF).ToLocalChecked())->ToNumber()->Uint32Value();
	fprintf(stdout, "kdf: %u\n", params->kdf);

	if (!v8Params->Get(Nan::New(STR_SHARED_DATA).ToLocalChecked())->IsUndefined()) {
		puts("ECDH1: Has shared data");
		GET_BUFFER(sharedData, v8Params->Get(Nan::New(STR_SHARED_DATA).ToLocalChecked())->ToObject());
		params->pSharedData = (CK_BYTE_PTR)malloc(sharedDataLen * sizeof(CK_BYTE));
		memcpy(params->pSharedData, sharedData, sharedDataLen);
		params->ulSharedDataLen = sharedDataLen;
	}

	GET_BUFFER(publicData, v8Params->Get(Nan::New(STR_PUBLIC_DATA).ToLocalChecked())->ToObject());
	params->pPublicData = (CK_BYTE_PTR)malloc(publicDataLen * sizeof(CK_BYTE));
	for (CK_ULONG i = 0; i < publicDataLen; i++)
		fprintf(stdout, "%02x", (unsigned char)publicData[i]);
	puts("");
	memcpy(params->pPublicData, publicData, publicDataLen);
	params->ulPublicDataLen = publicDataLen;
	fprintf(stdout, "PublicDataLen: %u\n", params->ulPublicDataLen);

	return params;
}

static Local<Object> c2v_ECDH1_DERIVE_PARAMS(ECDH1_DERIVE_PARAMS* params) {
	Nan::HandleScope();

	Local<Object> v8Res = Nan::New<Object>();

	v8Res->Set(Nan::New(STR_KDF).ToLocalChecked(), Nan::New<Number>(params->kdf));

	if (params->ulSharedDataLen) {
		v8Res->Set(Nan::New(STR_SHARED_DATA).ToLocalChecked(), Nan::CopyBuffer((char*)params->pSharedData, params->ulSharedDataLen).ToLocalChecked());
	}

	v8Res->Set(Nan::New(STR_PUBLIC_DATA).ToLocalChecked(), Nan::CopyBuffer((char*)params->pPublicData, params->ulPublicDataLen).ToLocalChecked());

	return v8Res;
}

typedef CK_MECHANISM MECHANISM;

static MECHANISM* MECHANISM_new() {
	MECHANISM* mech = (MECHANISM*)malloc(sizeof(MECHANISM));

	mech->mechanism = 0;
	mech->pParameter = NULL_PTR;
	mech->ulParameterLen = 0;

	return mech;
}

static void MECHANISM_free(MECHANISM* mechanism) {
	if (mechanism->pParameter)
		switch (mechanism->mechanism) {
		case CKM_ECDH1_DERIVE: {
			ECDH1_DERIVE_PARAMS_free((ECDH1_DERIVE_PARAMS*)mechanism->pParameter);
			break;
		}
		default:
			free(mechanism->pParameter);
		}
	free(mechanism);
}

static MECHANISM* v2c_MECHANISM(Local<Value> v8Mechanism) {
	Nan::HandleScope();

	if (!v8Mechanism->IsObject()) {
		return NULL;
	}

	Local<Object> v8Object = v8Mechanism->ToObject();

	Local<Value> v8MechType = v8Object->Get(Nan::New(STR_MECHANISM).ToLocalChecked());
	if (!v8MechType->IsNumber()) {
		return NULL;
	}

	Local<Value> v8Parameter = v8Object->Get(Nan::New(STR_PARAMETER).ToLocalChecked());
	if (!(v8Parameter->IsUndefined() || v8Parameter->IsNull() || node::Buffer::HasInstance(v8Parameter) || v8Parameter->IsObject())) {
		return NULL;
	}

	MECHANISM* attr = MECHANISM_new();

	attr->mechanism = v8MechType->ToNumber()->Uint32Value();
	if (!(v8Parameter->IsUndefined() || v8Parameter->IsNull())) {
		// Buffer
		switch (attr->mechanism) {
		case CKM_ECDH1_DERIVE: {
			ECDH1_DERIVE_PARAMS* params = v2c_ECDH1_DERIVE_PARAMS(v8Parameter->ToObject());
			if (!params)
				return NULL;
			attr->pParameter = params;
			attr->ulParameterLen = sizeof(*params);
			break;
		}
		default:
			GET_BUFFER(data, v8Parameter->ToObject());
			attr->pParameter = (char*)malloc(dataLen);
			memcpy(attr->pParameter, data, dataLen);
			attr->ulParameterLen = dataLen;
		}
	}

	return attr;
}

// static Local<Object> c2v_MECHANISM(MECHANISM* mechanism) {
// 	Nan::HandleScope();

// 	Local<Object> v8Mechanism = Nan::New<Object>();
// 	// Mechanism
// 	v8Mechanism->Set(Nan::New(STR_MECHANISM).ToLocalChecked(), Nan::New<Number>(mechanism->mechanism));

// 	// Parameter
// 	Local<Object> v8Parameter = node::Buffer::Copy(Isolate::GetCurrent(), (char *)mechanism->pParameter, mechanism->ulParameterLen).ToLocalChecked();
// 	v8Mechanism->Set(Nan::New(STR_PARAMETER).ToLocalChecked(), v8Parameter);

// 	return v8Mechanism;
// }

typedef CK_ATTRIBUTE ATTRIBUTE;

static ATTRIBUTE* ATTRIBUTE_new() {
	ATTRIBUTE* attr = (ATTRIBUTE*)malloc(sizeof(ATTRIBUTE));

	attr->type = 0;
	attr->pValue = NULL_PTR;
	attr->ulValueLen = 0;

	return attr;
}

static void ATTRIBUTE_free(ATTRIBUTE* attr) {
	if (attr->pValue)
		free(attr->pValue);
	// free(attr);
}

static ATTRIBUTE* v2c_ATTRIBUTE(Local<Value> v8Attribute) {
	Nan::HandleScope();

	if (!v8Attribute->IsObject()) {
		// Nan::ThrowTypeError("Parameter 1 must be Object");
		return NULL;
	}

	Local<Object> v8Object = v8Attribute->ToObject();

	Local<Value> v8Type = v8Object->Get(Nan::New(STR_TYPE).ToLocalChecked());
	if (!v8Type->IsNumber()) {
		// Nan::ThrowError("Parameter 'type' of Attribute is REQUIRED and MUST be Number");
		return NULL;
	}

	Local<Value> v8Value = v8Object->Get(Nan::New(STR_VALUE).ToLocalChecked());
	if (!(v8Value->IsUndefined() || v8Value->IsNull() ||
		node::Buffer::HasInstance(v8Value) ||
		v8Value->IsBoolean() ||
		v8Value->IsString() ||
		v8Value->IsNumber())) {
		// Nan::ThrowError("Parameter 'value' of Attribute MUST be Null or Buffer");
		return NULL;
	}

	ATTRIBUTE* attr = ATTRIBUTE_new();

	attr->type = v8Type->ToNumber()->Uint32Value();
	if (node::Buffer::HasInstance(v8Value)) {
		// Buffer
		GET_BUFFER(data, v8Value);
		attr->pValue = (char*)malloc(dataLen);
		memcpy(attr->pValue, data, dataLen);
		attr->ulValueLen = dataLen;
	}
	else if (v8Value->IsBoolean()) {
		// Boolean
		attr->pValue = (char*)malloc(1);
		((char*)attr->pValue)[0] = v8Value->ToBoolean()->Value();
		attr->ulValueLen = 1;
	}
	else if (v8Value->IsNumber()) {
		// Number
		CK_ULONG num = v8Value->ToNumber()->Uint32Value();

		uint32_t long_size = sizeof(CK_ULONG);

		attr->pValue = (char*)malloc(long_size);
		for (uint32_t i = 0; i < long_size; i++)
			((char*)attr->pValue)[i] = (char)(num >> (i * 8));
		attr->ulValueLen = long_size;
	}
	else if (v8Value->IsString()) {
		// String
		String::Utf8Value utf8Val(v8Value);
		char* val = *utf8Val;
		int valLen = utf8Val.length();
		attr->pValue = (char*)malloc(valLen);
		memcpy(attr->pValue, val, valLen);
		attr->ulValueLen = valLen;
	}

	return attr;
}

static Local<Object> c2v_ATTRIBUTE(ATTRIBUTE* attr) {
	Nan::HandleScope();

	Local<Object> v8Attribute = Nan::New<Object>();
	// Type
	v8Attribute->Set(Nan::New(STR_TYPE).ToLocalChecked(), Nan::New<Number>(attr->type));

	// Value
	Local<Object> v8Value = node::Buffer::Copy(Isolate::GetCurrent(), (char *)attr->pValue, attr->ulValueLen).ToLocalChecked();
	v8Attribute->Set(Nan::New(STR_VALUE).ToLocalChecked(), v8Value);

	return v8Attribute;
}

struct TEMPLATE {
	uint32_t size;
	ATTRIBUTE* items;
};

static TEMPLATE* TEMPLATE_new(int size) {
	TEMPLATE* tmpl = (TEMPLATE*)malloc(sizeof(TEMPLATE));

	tmpl->items = (ATTRIBUTE*)malloc(size * sizeof(ATTRIBUTE));
	tmpl->size = size;

	return tmpl;
}

static TEMPLATE* TEMPLATE_new() {
	return TEMPLATE_new(0);
}

static void TEMPLATE_free(TEMPLATE* tmpl) {
	for (uint32_t i = 0; i < tmpl->size; i++) {
		ATTRIBUTE_free(&tmpl->items[i]);
	}
	free(tmpl);
}

static void TEMPLATE_push(TEMPLATE* tmpl, ATTRIBUTE* attr) {
	if (tmpl && attr) {
		tmpl->items = (ATTRIBUTE*)realloc(tmpl->items, ++tmpl->size * sizeof(ATTRIBUTE));
		tmpl->items[tmpl->size - 1] = *attr;
	}
}

static TEMPLATE* v2c_TEMPLATE(Local<Object> v8Template) {
	Nan::HandleScope();

	uint32_t templateLen = v8Template->Get(Nan::New("length").ToLocalChecked())->ToNumber()->Uint32Value();

	uint32_t i = 0;
	TEMPLATE* pTemplate = TEMPLATE_new();
	for (i = 0; i < templateLen; i++) {
		Local<Value> v8Attribute = v8Template->Get(i);
		CK_ATTRIBUTE_PTR attr = v2c_ATTRIBUTE(v8Attribute);
		TEMPLATE_push(pTemplate, attr);
	}

	return pTemplate;
}

static Local<Array> c2v_TEMPLATE(TEMPLATE* tmpl) {
	Nan::HandleScope();

	Local<Array> v8Res = Nan::New<Array>();
	for (uint32_t i = 0; i < tmpl->size; i++) {
		ATTRIBUTE* pItem = &tmpl->items[i];
		Local<Object> v8Attribute = c2v_ATTRIBUTE(pItem);

		v8Res->Set(i, v8Attribute);
	}
	return v8Res;
}

static Handle<Object> GetVersion(CK_VERSION& version) {
	Nan::HandleScope();

	Local<Object> v8Version = Nan::New<Object>();
	v8Version->Set(Nan::New(STR_MAJOR).ToLocalChecked(), Nan::New(version.major));
	v8Version->Set(Nan::New(STR_MINOR).ToLocalChecked(), Nan::New(version.minor));

	return  v8Version;
}

static Local<Value> BufferSlice(Local<Object> buffer, uint32_t start, uint32_t end) {
	Nan::HandleScope();

	Local<Function> sliceFunction = Local<Function>::Cast(buffer->Get(Nan::New("slice").ToLocalChecked()));

	Local<Value> args[2];
	args[0] = Nan::New<Number>(start);
	args[1] = Nan::New<Number>(end);

	Local<Value> newBuffer = sliceFunction->Call(buffer, 2, args);
	return newBuffer;
}

#define CN_PKCS11 "PKCS11"

void PKCS11::Init(Handle<Object> exports) {
	Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
	tpl->SetClassName(Nan::New(CN_PKCS11).ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	// methods
	SetPrototypeMethod(tpl, "load", Load);
	SET_PKCS11_METHOD(C_Initialize);
	SET_PKCS11_METHOD(C_Finalize);
	SET_PKCS11_METHOD(C_GetInfo);
	SET_PKCS11_METHOD(C_GetSlotList);
	SET_PKCS11_METHOD(C_GetSlotInfo);
	SET_PKCS11_METHOD(C_GetTokenInfo);
	SET_PKCS11_METHOD(C_GetMechanismList);
	SET_PKCS11_METHOD(C_GetMechanismInfo);
	SET_PKCS11_METHOD(C_InitToken);
	SET_PKCS11_METHOD(C_InitPIN);
	SET_PKCS11_METHOD(C_SetPIN);
	SET_PKCS11_METHOD(C_OpenSession);
	SET_PKCS11_METHOD(C_CloseSession);
	SET_PKCS11_METHOD(C_CloseAllSessions);
	SET_PKCS11_METHOD(C_GetSessionInfo);
	SET_PKCS11_METHOD(C_Login);
	SET_PKCS11_METHOD(C_Logout);
	SET_PKCS11_METHOD(C_CreateObject);
	SET_PKCS11_METHOD(C_CopyObject);
	SET_PKCS11_METHOD(C_DestroyObject);
	SET_PKCS11_METHOD(C_GetObjectSize);
	SET_PKCS11_METHOD(C_FindObjectsInit);
	SET_PKCS11_METHOD(C_FindObjects);
	SET_PKCS11_METHOD(C_FindObjectsFinal);
	SET_PKCS11_METHOD(C_GetAttributeValue);
	SET_PKCS11_METHOD(C_SetAttributeValue);
	SET_PKCS11_METHOD(C_EncryptInit);
	SET_PKCS11_METHOD(C_Encrypt);
	SET_PKCS11_METHOD(C_EncryptUpdate);
	SET_PKCS11_METHOD(C_EncryptFinal);
	SET_PKCS11_METHOD(C_DecryptInit);
	SET_PKCS11_METHOD(C_Decrypt);
	SET_PKCS11_METHOD(C_DecryptUpdate);
	SET_PKCS11_METHOD(C_DecryptFinal);
	SET_PKCS11_METHOD(C_DigestInit);
	SET_PKCS11_METHOD(C_Digest);
	SET_PKCS11_METHOD(C_DigestUpdate);
	SET_PKCS11_METHOD(C_DigestFinal);
	SET_PKCS11_METHOD(C_DigestKey);
	SET_PKCS11_METHOD(C_SignInit);
	SET_PKCS11_METHOD(C_Sign);
	SET_PKCS11_METHOD(C_SignUpdate);
	SET_PKCS11_METHOD(C_SignFinal);
	SET_PKCS11_METHOD(C_SignRecoverInit);
	SET_PKCS11_METHOD(C_SignRecover);
	SET_PKCS11_METHOD(C_VerifyInit);
	SET_PKCS11_METHOD(C_Verify);
	SET_PKCS11_METHOD(C_VerifyUpdate);
	SET_PKCS11_METHOD(C_VerifyFinal);
	SET_PKCS11_METHOD(C_VerifyRecoverInit);
	SET_PKCS11_METHOD(C_VerifyRecover);
	SET_PKCS11_METHOD(C_GenerateKey);
	SET_PKCS11_METHOD(C_GenerateKeyPair);
	SET_PKCS11_METHOD(C_WrapKey);
	SET_PKCS11_METHOD(C_UnwrapKey);
	SET_PKCS11_METHOD(C_DeriveKey);
	SET_PKCS11_METHOD(C_SeedRandom);
	SET_PKCS11_METHOD(C_GenerateRandom);

	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	// static methods
	// Nan::SetMethod<Local<Object>>(tpl->GeFunction(), "generate", Generate);

	exports->Set(Nan::New(CN_PKCS11).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(PKCS11::New) {
	if (info.IsConstructCall()) {

		PKCS11* obj = new PKCS11();
		obj->Wrap(info.This());

		declare_objects(info.This());
		declare_attributes(info.This());
		declare_ket_types(info.This());
		declare_mechanisms(info.This());

		info.GetReturnValue().Set(info.This());
	}
	else {
		Local<Function> cons = Nan::New(constructor());
		info.GetReturnValue().Set(Nan::NewInstance(cons, 0, nullptr).ToLocalChecked());
	}
};

NAN_METHOD(PKCS11::Load) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, String);
	String::Utf8Value v8Path(info[0]->ToString());

	int mode = RTLD_LAZY;

	UNWRAP_PKCS11;

	__pkcs11->dlHandle = dlopen(*v8Path, mode);
	if (!__pkcs11->dlHandle) {
		Nan::ThrowError(Nan::New(dlerror()).ToLocalChecked());
		return;
	}

	// reset errors
	dlerror();
	CK_C_GetFunctionList f_C_GetFunctionList = (CK_C_GetFunctionList)dlsym(__pkcs11->dlHandle, "C_GetFunctionList");
	const char *dlsym_error = dlerror();
	if (dlsym_error) {
		dlclose(__pkcs11->dlHandle);
		Nan::ThrowError(Nan::New("Cannot load symbol 'C_GetFunctionList'").ToLocalChecked());
		return;
	}

	CHECK_PKCS11_RV(f_C_GetFunctionList(&__pkcs11->functionList));

	info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(PKCS11::C_Initialize) {
	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_Initialize(NULL_PTR));
	// TODO: initialized
}

NAN_METHOD(PKCS11::C_Finalize) {

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_Finalize(NULL_PTR));
}

NAN_METHOD(PKCS11::C_GetInfo) {
	UNWRAP_PKCS11;

	CK_INFO _info;
	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetInfo(&_info));

	Local<Object> v8Object = Nan::New<Object>();
	if (_info.cryptokiVersion.major == 2) {
		/* Do lots of interesting cryptographic things with the token */
		v8Object->Set(Nan::New(STR_CRYPTOKI_VERSION).ToLocalChecked(), GetVersion(_info.cryptokiVersion));
		v8Object->Set(Nan::New(STR_MANUFACTURER_ID).ToLocalChecked(), Nan::New((char*)_info.manufacturerID, 32).ToLocalChecked());
		v8Object->Set(Nan::New(STR_FLAGS).ToLocalChecked(), Nan::New((uint32_t)_info.flags));

		v8Object->Set(Nan::New(STR_LIBRARY_DESCRIPTION).ToLocalChecked(), Nan::New((char*)_info.libraryDescription, 32).ToLocalChecked());
		v8Object->Set(Nan::New(STR_LIBRARY_VERSION).ToLocalChecked(), GetVersion(_info.libraryVersion));
	}

	info.GetReturnValue().Set(v8Object);
}

// CK_BBOOL       tokenPresent,  /* only slots with tokens? */
// CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
// CK_ULONG_PTR   pulCount       /* receives number of slots */
NAN_METHOD(PKCS11::C_GetSlotList) {
	CK_BBOOL tokenPresent = info[0]->ToBoolean()->Value();
	CK_SLOT_ID_PTR pSlotList;
	CK_ULONG   ulCount;

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetSlotList(tokenPresent, NULL_PTR, &ulCount));
	pSlotList = (CK_SLOT_ID_PTR)malloc(ulCount * sizeof(CK_SLOT_ID));
	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetSlotList(tokenPresent, pSlotList, &ulCount));

	Local<Array> v8SlotList = Nan::New<Array>();
	for (uint32_t i = 0; i < ulCount; i++) {
		v8SlotList->Set(i, Nan::New<Number>(pSlotList[i]));
	}

	free(pSlotList);

	info.GetReturnValue().Set(v8SlotList);
}

// CK_SLOT_ID       slotID,  /* the ID of the slot */
// CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
NAN_METHOD(PKCS11::C_GetSlotInfo) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SLOT_ID slotID = info[0]->ToNumber()->Uint32Value();
	CK_SLOT_INFO _info;

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetSlotInfo(slotID, &_info));

	Local<Object> v8Object = Nan::New<Object>();

	v8Object->Set(Nan::New(STR_SLOT_DESCRIPTION).ToLocalChecked(), Nan::New((char*)_info.slotDescription, 64).ToLocalChecked());
	v8Object->Set(Nan::New(STR_MANUFACTURER_ID).ToLocalChecked(), Nan::New((char*)_info.manufacturerID, 32).ToLocalChecked());
	v8Object->Set(Nan::New(STR_FLAGS).ToLocalChecked(), Nan::New((uint32_t)_info.flags));
	v8Object->Set(Nan::New(STR_HARDWARE_VERSION).ToLocalChecked(), GetVersion(_info.hardwareVersion));
	v8Object->Set(Nan::New(STR_FIRMWARE_VERSION).ToLocalChecked(), GetVersion(_info.firmwareVersion));

	info.GetReturnValue().Set(v8Object);
}

// CK_SLOT_ID        slotID,  /* ID of the token's slot */
// CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
NAN_METHOD(PKCS11::C_GetTokenInfo) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	uint32_t slotID = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CK_TOKEN_INFO _info;
	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetTokenInfo(slotID, &_info));

	Local<Object> v8Object = Nan::New<Object>();
	v8Object->Set(Nan::New(STR_LABEL).ToLocalChecked(), Nan::New((char*)_info.label, 32).ToLocalChecked());
	v8Object->Set(Nan::New(STR_MANUFACTURER_ID).ToLocalChecked(), Nan::New((char*)_info.manufacturerID, 32).ToLocalChecked());
	v8Object->Set(Nan::New(STR_MODEL).ToLocalChecked(), Nan::New((char*)_info.model, 16).ToLocalChecked());
	v8Object->Set(Nan::New(STR_SERIAL_NUMER).ToLocalChecked(), Nan::New((char*)_info.serialNumber, 16).ToLocalChecked());
	v8Object->Set(Nan::New(STR_FLAGS).ToLocalChecked(), Nan::New<Number>(_info.flags));
	v8Object->Set(Nan::New(STR_MAX_SESSION_COUNT).ToLocalChecked(), Nan::New<Number>(_info.ulMaxSessionCount));
	v8Object->Set(Nan::New(STR_SESSION_COUNT).ToLocalChecked(), Nan::New<Number>(_info.ulSessionCount));
	v8Object->Set(Nan::New(STR_MAX_RW_SESSION_COUNT).ToLocalChecked(), Nan::New<Number>(_info.ulMaxRwSessionCount));
	v8Object->Set(Nan::New(STR_RW_SESSION_COUNT).ToLocalChecked(), Nan::New<Number>(_info.ulRwSessionCount));
	v8Object->Set(Nan::New(STR_MAX_PIN_LEN).ToLocalChecked(), Nan::New<Number>(_info.ulMaxPinLen));
	v8Object->Set(Nan::New(STR_MIN_PIN_LEN).ToLocalChecked(), Nan::New<Number>(_info.ulMinPinLen));
	v8Object->Set(Nan::New(STR_HARDWARE_VERSION).ToLocalChecked(), GetVersion(_info.hardwareVersion));
	v8Object->Set(Nan::New(STR_FIRMWARE_VERSION).ToLocalChecked(), GetVersion(_info.firmwareVersion));
	v8Object->Set(Nan::New(STR_UTC_TIME).ToLocalChecked(), Nan::New((char*)_info.utcTime, 16).ToLocalChecked());

	info.GetReturnValue().Set(v8Object);
}

// CK_SLOT_ID            slotID,          /* ID of token's slot */
// CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
// CK_ULONG_PTR          pulCount         /* gets # of mechs. */
NAN_METHOD(PKCS11::C_GetMechanismList) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SLOT_ID slotID = info[0]->ToNumber()->Uint32Value();

	CK_MECHANISM_TYPE_PTR pMechanismList;
	CK_ULONG ulCount;

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetMechanismList(slotID, NULL_PTR, &ulCount));
	pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulCount * sizeof(CK_MECHANISM_TYPE));
	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetMechanismList(slotID, pMechanismList, &ulCount));

	Local<Array> v8Res = Nan::New<Array>();
	for (uint32_t i = 0; i < ulCount; i++) {
		v8Res->Set(i, Nan::New<Number>(pMechanismList[i]));
	}
	info.GetReturnValue().Set(v8Res);
}

// CK_SLOT_ID            slotID,  /* ID of the token's slot */
// CK_MECHANISM_TYPE     type,    /* type of mechanism */
// CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
NAN_METHOD(PKCS11::C_GetMechanismInfo) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SLOT_ID slotID = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Number);
	CK_MECHANISM_TYPE type = info[1]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CK_MECHANISM_INFO pInfo;
	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetMechanismInfo(slotID, type, &pInfo));

	Local<Object> v8Res = Nan::New<Object>();

	v8Res->Set(Nan::New(STR_MIN_KEY_SIZE).ToLocalChecked(), Nan::New<Number>(pInfo.ulMinKeySize));
	v8Res->Set(Nan::New(STR_MAX_KEY_SIZE).ToLocalChecked(), Nan::New<Number>(pInfo.ulMaxKeySize));
	v8Res->Set(Nan::New(STR_FLAGS).ToLocalChecked(), Nan::New<Number>(pInfo.flags));

	info.GetReturnValue().Set(v8Res);
}


/* C_InitToken initializes a token. */
// CK_SLOT_ID      slotID,    /* ID of the token's slot */
// CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
// CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
// CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
NAN_METHOD(PKCS11::C_InitToken) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SLOT_ID      slotID = info[0]->ToNumber()->Uint32Value();

	CK_ULONG        pinLen = 0;
	CK_UTF8CHAR label[32];

	UNWRAP_PKCS11;

	std::string pin;
	if (info[1]->IsString()) {
		pin = std::string(*String::Utf8Value(info[1]));
		pinLen = (CK_ULONG)pin.length();
	}
	CHECK_PKCS11_RV(__pkcs11->functionList->C_InitToken(slotID, pinLen ? (CK_UTF8CHAR_PTR)pin.c_str() : NULL_PTR, pinLen, label));

	info.GetReturnValue().Set(Nan::New((char*)label).ToLocalChecked());
}

NAN_METHOD(PKCS11::C_InitPIN) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CK_ULONG        pinLen = 0;

	UNWRAP_PKCS11;

	std::string pin;
	if (info[1]->IsString()) {
		pin = std::string(*String::Utf8Value(info[1]));
		pinLen = (CK_ULONG)pin.length();
	}

	CHECK_PKCS11_RV(__pkcs11->functionList->C_InitPIN(hSession, pinLen ? (CK_UTF8CHAR_PTR)pin.c_str() : NULL_PTR, pinLen));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_SetPIN) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	std::string oldPin;
	std::string newPin;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)oldPin.c_str(), (CK_ULONG)oldPin.length(), (CK_UTF8CHAR_PTR)newPin.c_str(), (CK_ULONG)newPin.length()));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_OpenSession) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SLOT_ID hSLot = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Number);
	CK_FLAGS flags = info[1]->ToNumber()->Uint32Value();
	CK_SESSION_HANDLE hSession;

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_OpenSession(hSLot, flags, NULL_PTR, NULL_PTR, &hSession));

	info.GetReturnValue().Set(Nan::New<Number>(hSession));
}

NAN_METHOD(PKCS11::C_CloseSession) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_CloseSession(hSession));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_CloseAllSessions) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SLOT_ID hSlot = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_CloseAllSessions(hSlot));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_GetSessionInfo) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();
	CK_SESSION_INFO _info;

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetSessionInfo(hSession, &_info));

	Local<Object> v8Res = Nan::New<Object>();

	v8Res->Set(Nan::New(STR_SLOT_ID).ToLocalChecked(), Nan::New<Number>(_info.slotID));
	v8Res->Set(Nan::New(STR_STATE).ToLocalChecked(), Nan::New<Number>(_info.state));
	v8Res->Set(Nan::New(STR_FLAGS).ToLocalChecked(), Nan::New<Number>(_info.flags));
	v8Res->Set(Nan::New(STR_DEVICE_ERROR).ToLocalChecked(), Nan::New<Number>(_info.ulDeviceError));

	info.GetReturnValue().Set(v8Res);
}

NAN_METHOD(PKCS11::C_Login) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Number);
	CK_USER_TYPE userType = info[1]->ToNumber()->Uint32Value();
	CK_ULONG pinLen = 0;

	UNWRAP_PKCS11;

	std::string pin;
	if (info[2]->IsString()) {
		pin = std::string(*String::Utf8Value(info[2]));
		pinLen = (CK_ULONG)pin.length();
	}

	CHECK_PKCS11_RV(__pkcs11->functionList->C_Login(hSession, userType, pinLen ? (CK_UTF8CHAR_PTR)pin.c_str() : NULL_PTR, pinLen));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_Logout) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_Logout(hSession));

	info.GetReturnValue().SetNull();
}

// CK_SESSION_HANDLE hSession,   /* the session's handle */
// CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
// CK_ULONG          ulCount     /* attrs in search template */
NAN_METHOD(PKCS11::C_FindObjectsInit) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Get Template 
	if (!(info[1]->IsUndefined() || info[1]->IsNull() || info[1]->IsArray())) {
		Nan::ThrowTypeError("Parameter 2 MUST be Empty or Array");
		return;
	}

	UNWRAP_PKCS11;

	TEMPLATE* pTemplate = NULL_PTR;
	uint32_t templateLen = 0;
	if (!(info[1]->IsUndefined() || info[1]->IsNull())) {
		pTemplate = v2c_TEMPLATE(info[1]->ToObject());
		templateLen = pTemplate->size;
	}

	CK_RV rv = __pkcs11->functionList->C_FindObjectsInit(hSession, pTemplate ? pTemplate->items : NULL_PTR, templateLen);
	if (rv != CKR_OK) {
		if (pTemplate)
			TEMPLATE_free(pTemplate);
		THROW_PKCS11_ERROR(rv);
		return;
	}

	if (pTemplate)
		TEMPLATE_free(pTemplate);
	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_FindObjects) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CK_ULONG ulObjectCount;
	CK_OBJECT_HANDLE hObject;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_FindObjects(hSession, &hObject, 1, &ulObjectCount));

	Local<Value> v8Res = ulObjectCount ? Nan::New<Number>(hObject).As<Value>() : Nan::Null().As<Value>();

	info.GetReturnValue().Set(v8Res);
}

NAN_METHOD(PKCS11::C_FindObjectsFinal) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_FindObjectsFinal(hSession));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_GetAttributeValue) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Number);
	CK_OBJECT_HANDLE hObject = info[1]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Object);
	TEMPLATE* pTemplate = v2c_TEMPLATE(info[2]->ToObject());
	CK_RV rv = __pkcs11->functionList->C_GetAttributeValue(hSession, hObject, pTemplate->items, pTemplate->size);
	if (rv != CKR_OK) {
		THROW_PKCS11_ERROR(rv);
		TEMPLATE_free(pTemplate);
		return;
	}

	for (uint32_t i = 0; i < pTemplate->size; i++) {
		pTemplate->items[i].pValue = (CK_BYTE_PTR)malloc(pTemplate->items[i].ulValueLen);
	}

	rv = __pkcs11->functionList->C_GetAttributeValue(hSession, hObject, pTemplate->items, pTemplate->size);
	if (rv != CKR_OK) {
		THROW_PKCS11_ERROR(rv);
		TEMPLATE_free(pTemplate);
		return;
	}

	Local<Array> v8Res = c2v_TEMPLATE(pTemplate);
	TEMPLATE_free(pTemplate);

	info.GetReturnValue().Set(v8Res);
}

NAN_METHOD(PKCS11::C_SetAttributeValue) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Number);
	CK_OBJECT_HANDLE hObject = info[1]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Object);

	TEMPLATE* pTemplate = v2c_TEMPLATE(info[2]->ToObject());
	CK_RV rv = __pkcs11->functionList->C_SetAttributeValue(hSession, hObject, pTemplate->items, pTemplate->size);
	if (rv != CKR_OK) {
		THROW_PKCS11_ERROR(rv);
		TEMPLATE_free(pTemplate);
		return;
	}

	TEMPLATE_free(pTemplate);

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_CreateObject) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Array);
	TEMPLATE* tmpl = v2c_TEMPLATE(info[1]->ToObject());
	CK_OBJECT_HANDLE hObject;
	CK_RV rv = __pkcs11->functionList->C_CreateObject(hSession, tmpl->items, tmpl->size, &hObject);
	if (rv != CKR_OK) {
		TEMPLATE_free(tmpl);
		THROW_PKCS11_ERROR(rv);
		return;
	}

	TEMPLATE_free(tmpl);

	info.GetReturnValue().Set(Nan::New<Number>(hObject));
}

NAN_METHOD(PKCS11::C_CopyObject) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();
	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Number);
	CK_OBJECT_HANDLE hObject = info[1]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Object);
	TEMPLATE* tmpl = v2c_TEMPLATE(info[2]->ToObject());
	CK_OBJECT_HANDLE hNewObject;
	CK_RV rv = __pkcs11->functionList->C_CopyObject(hSession, hObject, tmpl->items, tmpl->size, &hNewObject);
	if (rv != CKR_OK) {
		TEMPLATE_free(tmpl);
		THROW_PKCS11_ERROR(rv);
		return;
	}

	info.GetReturnValue().Set(Nan::New<Number>(hNewObject));
}

NAN_METHOD(PKCS11::C_DestroyObject) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Number);
	CK_OBJECT_HANDLE hObject = info[1]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_DestroyObject(hSession, hObject));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_GetObjectSize) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	CHECK_TYPE(1, Number);
	CK_OBJECT_HANDLE hObject = info[1]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CK_ULONG ulSize;
	CHECK_PKCS11_RV(__pkcs11->functionList->C_GetObjectSize(hSession, hObject, &ulSize));

	info.GetReturnValue().Set(Nan::New<Number>(ulSize));
}

NAN_METHOD(PKCS11::C_EncryptInit) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();
	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_SESSION_HANDLE hObject = info[2]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	CK_RV rv = __pkcs11->functionList->C_EncryptInit(hSession, mech, hObject);
	if (rv) {
		THROW_PKCS11_ERROR(rv);
		MECHANISM_free(mech);
		return;
	}

	MECHANISM_free(mech);

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_Encrypt) {
	Nan::ThrowError("Method is not implemented");
}

NAN_METHOD(PKCS11::C_EncryptUpdate) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 MUST be Buffer");
		return;
	}

	CHECK_REQUIRED(2);
	if (!node::Buffer::HasInstance(info[2])) {
		Nan::ThrowTypeError("Parameter 3 MUST be Buffer");
		return;
	}

	// Part
	GET_BUFFER_ARGS(part, 1);

	// EncryptedPart
	GET_BUFFER_ARGS(encPart, 2);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_EncryptUpdate(hSession, (CK_BYTE_PTR)part, partLen, (CK_BYTE_PTR)encPart, &encPartLen));

	Local<Object> v8EncPart = info[2]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8EncPart, 0, encPartLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_EncryptFinal) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(1);
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 MUST be Buffer");
		return;
	}

	// Last encrypted part
	GET_BUFFER_ARGS(encPart, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_EncryptFinal(hSession, (CK_BYTE_PTR)encPart, &encPartLen));

	Local<Object> v8EncPart = info[1]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8EncPart, 0, encPartLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_DecryptInit) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_SESSION_HANDLE hObject = info[2]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	CK_RV rv = __pkcs11->functionList->C_DecryptInit(hSession, mech, hObject);
	if (rv) {
		THROW_PKCS11_ERROR(rv);
		MECHANISM_free(mech);
		return;
	}

	MECHANISM_free(mech);

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_Decrypt) {
	Nan::ThrowError("Method is not implemented");
}

NAN_METHOD(PKCS11::C_DecryptUpdate) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}
	if (!node::Buffer::HasInstance(info[2])) {
		Nan::ThrowTypeError("Parameter 3 is REQUIRED and MUST be Buffer");
		return;
	}

	// Part
	GET_BUFFER_ARGS(part, 1);

	// Decrypted part
	GET_BUFFER_ARGS(decPart, 2);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_DecryptUpdate(hSession, (CK_BYTE_PTR)part, partLen, (CK_BYTE_PTR)decPart, &decPartLen));

	Local<Object> v8DecPart = info[2]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8DecPart, 0, decPartLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_DecryptFinal) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}

	// Last decrypted part
	GET_BUFFER_ARGS(decPart, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_DecryptFinal(hSession, (CK_BYTE_PTR)decPart, &decPartLen));

	Local<Object> v8DecPart = info[1]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8DecPart, 0, decPartLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_DigestInit) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	CK_RV rv = __pkcs11->functionList->C_DigestInit(hSession, mech);
	if (rv) {
		THROW_PKCS11_ERROR(rv);
		MECHANISM_free(mech);
		return;
	}

	MECHANISM_free(mech);

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_Digest) {
	Nan::ThrowError("Method is not implemented");
}

NAN_METHOD(PKCS11::C_DigestUpdate) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}

	// Part
	GET_BUFFER_ARGS(part, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_DigestUpdate(hSession, (CK_BYTE_PTR)part, partLen));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_DigestFinal) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}

	// Last decrypted part
	GET_BUFFER_ARGS(hash, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_DigestFinal(hSession, (CK_BYTE_PTR)hash, &hashLen));

	Local<Object> v8DecPart = info[1]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8DecPart, 0, hashLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_DigestKey) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_OBJECT_HANDLE hObject = info[1]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_DigestKey(hSession, hObject));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_SignInit) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_OBJECT_HANDLE hObject = info[2]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	CK_RV rv = __pkcs11->functionList->C_SignInit(hSession, mech, hObject);
	if (rv) {
		THROW_PKCS11_ERROR(rv);
		MECHANISM_free(mech);
		return;
	}

	MECHANISM_free(mech);

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_Sign) {
	Nan::ThrowError("Method is not implemented");
}

NAN_METHOD(PKCS11::C_SignUpdate) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}

	// Part
	GET_BUFFER_ARGS(part, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_SignUpdate(hSession, (CK_BYTE_PTR)part, partLen));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_SignFinal) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Signature
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(signature, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_SignFinal(hSession, (CK_BYTE_PTR)signature, &signatureLen));

	Local<Object> v8Signature = info[1]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8Signature, 0, signatureLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_SignRecoverInit) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_SESSION_HANDLE hObject = info[2]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	CK_RV rv = __pkcs11->functionList->C_SignRecoverInit(hSession, mech, hObject);
	MECHANISM_free(mech);
	if (rv) {
		THROW_PKCS11_ERROR(rv);
		return;
	}

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_SignRecover) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Data
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(data, 1);

	// Signature
	if (!node::Buffer::HasInstance(info[2])) {
		Nan::ThrowTypeError("Parameter 3 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(signature, 2);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_SignRecover(hSession, (CK_BYTE_PTR)data, dataLen, (CK_BYTE_PTR)signature, &signatureLen));

	Local<Object> v8Signature = info[2]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8Signature, 0, signatureLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_VerifyInit) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_OBJECT_HANDLE hObject = info[2]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	CK_RV rv = __pkcs11->functionList->C_VerifyInit(hSession, mech, hObject);
	if (rv) {
		THROW_PKCS11_ERROR(rv);
		MECHANISM_free(mech);
		return;
	}

	MECHANISM_free(mech);

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_Verify) {
	Nan::ThrowError("Method is not implemented");
}

NAN_METHOD(PKCS11::C_VerifyUpdate) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}

	// Part
	GET_BUFFER_ARGS(part, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_VerifyUpdate(hSession, (CK_BYTE_PTR)part, partLen));

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_VerifyFinal) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Signature
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(signature, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_VerifyFinal(hSession, (CK_BYTE_PTR)signature, signatureLen));

	info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));
}

NAN_METHOD(PKCS11::C_VerifyRecoverInit) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_OBJECT_HANDLE hObject = info[2]->ToNumber()->Uint32Value();

	UNWRAP_PKCS11;

	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	CK_RV rv = __pkcs11->functionList->C_VerifyRecoverInit(hSession, mech, hObject);
	MECHANISM_free(mech);
	if (rv) {
		THROW_PKCS11_ERROR(rv);
		return;
	}

	info.GetReturnValue().SetNull();
}

NAN_METHOD(PKCS11::C_VerifyRecover) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Signature
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(signature, 1);

	// Data
	if (!node::Buffer::HasInstance(info[2])) {
		Nan::ThrowTypeError("Parameter 3 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(data, 2);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_VerifyRecover(hSession, (CK_BYTE_PTR)signature, signatureLen, (CK_BYTE_PTR)data, &dataLen));

	Local<Object> v8Data = info[2]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8Data, 0, dataLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_GenerateKey) {
	// Session
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Mechanism
	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	// Key template
	if ((info[2]->IsUndefined() || info[2]->IsNull())) {
		Nan::ThrowTypeError("Paramter 3 is REQUIERD and MUST be Object");
		MECHANISM_free(mech);
		return;
	}
	TEMPLATE* pTemplate = v2c_TEMPLATE(info[2]->ToObject());

	// Object
	CK_ULONG hObject;

	UNWRAP_PKCS11;

	CK_RV rv = __pkcs11->functionList->C_GenerateKey(hSession, mech, pTemplate->items, pTemplate->size, &hObject);
	MECHANISM_free(mech);
	TEMPLATE_free(pTemplate);
	if (rv != CKR_OK) {
		THROW_PKCS11_ERROR(rv);
		return;
	}

	info.GetReturnValue().Set(Nan::New<Number>(hObject));
}

NAN_METHOD(PKCS11::C_GenerateKeyPair) {
	// Session
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Mechanism
	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	// Public key template
	if ((info[2]->IsUndefined() || info[2]->IsNull())) {
		Nan::ThrowTypeError("Paramter 3 is REQUIERD and MUST be Object");
		MECHANISM_free(mech);
		return;
	}
	TEMPLATE* pPublicKeyTemplate = v2c_TEMPLATE(info[2]->ToObject());

	// Private key template
	if ((info[3]->IsUndefined() || info[3]->IsNull())) {
		Nan::ThrowTypeError("Paramter 4 is REQUIERD and MUST be Object");
		MECHANISM_free(mech);
		TEMPLATE_free(pPublicKeyTemplate);
		return;
	}
	TEMPLATE* pPrivateKeyTemplate = v2c_TEMPLATE(info[3]->ToObject());

	// Keys
	CK_ULONG hPublicKey;
	CK_ULONG hPrivateKey;

	UNWRAP_PKCS11;

	CK_RV rv = __pkcs11->functionList->C_GenerateKeyPair(hSession, mech, pPublicKeyTemplate->items, pPublicKeyTemplate->size, pPrivateKeyTemplate->items, pPrivateKeyTemplate->size, &hPublicKey, &hPrivateKey);
	MECHANISM_free(mech);
	TEMPLATE_free(pPublicKeyTemplate);
	TEMPLATE_free(pPrivateKeyTemplate);
	if (rv != CKR_OK) {
		THROW_PKCS11_ERROR(rv);
		return;
	}

	// Result
	Local<Object> v8Result = Nan::New<Object>();
	v8Result->Set(Nan::New(STR_PRIVATE_KEY).ToLocalChecked(), Nan::New<Number>(hPrivateKey));
	v8Result->Set(Nan::New(STR_PUBLIC_KEY).ToLocalChecked(), Nan::New<Number>(hPublicKey));

	info.GetReturnValue().Set(v8Result);
}

NAN_METHOD(PKCS11::C_WrapKey) {
	// Session
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_OBJECT_HANDLE hWrappingKey = info[2]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(3);
	CHECK_TYPE(3, Number);
	CK_OBJECT_HANDLE hKey = info[3]->ToNumber()->Uint32Value();

	// Mechanism
	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	// Wrapped key
	if (!node::Buffer::HasInstance(info[4])) {
		Nan::ThrowTypeError("Parameter 5 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(wrappedKey, 4);


	UNWRAP_PKCS11;

	CK_RV rv = __pkcs11->functionList->C_WrapKey(hSession, mech, hWrappingKey, hKey, (CK_BYTE_PTR)wrappedKey, &wrappedKeyLen);
	MECHANISM_free(mech);
	if (rv != CKR_OK) {
		THROW_PKCS11_ERROR(rv);
		return;
	}

	Local<Object> v8Data = info[2]->ToObject();
	Local<Value> newBuffer = BufferSlice(v8Data, 0, wrappedKeyLen);

	info.GetReturnValue().Set(newBuffer);
}

NAN_METHOD(PKCS11::C_UnwrapKey) {
	// Session
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_OBJECT_HANDLE hUnwrappingKey = info[2]->ToNumber()->Uint32Value();

	// Wrapped key
	if (!node::Buffer::HasInstance(info[3])) {
		Nan::ThrowTypeError("Parameter 4 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(wrappedKey, 3);

	// Mechanism
	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	// Key template
	if ((info[4]->IsUndefined() || info[4]->IsNull())) {
		Nan::ThrowTypeError("Paramter 5 is REQUIERD and MUST be Object");
		MECHANISM_free(mech);
		return;
	}
	TEMPLATE* pTemplate = v2c_TEMPLATE(info[4]->ToObject());

	CK_OBJECT_HANDLE hKey;

	UNWRAP_PKCS11;

	CK_RV rv = __pkcs11->functionList->C_UnwrapKey(hSession, mech, hUnwrappingKey, (CK_BYTE_PTR)wrappedKey, wrappedKeyLen, pTemplate->items, pTemplate->size, &hKey);
	MECHANISM_free(mech);
	TEMPLATE_free(pTemplate);
	if (rv != CKR_OK) {
		THROW_PKCS11_ERROR(rv);
		return;
	}

	info.GetReturnValue().Set(Nan::New<Number>(hKey));
}

NAN_METHOD(PKCS11::C_DeriveKey) {
	// Session
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();
	CHECK_REQUIRED(2);
	CHECK_TYPE(2, Number);
	CK_OBJECT_HANDLE hBaseKey = info[2]->ToNumber()->Uint32Value();

	// Mechanism
	MECHANISM* mech = v2c_MECHANISM(info[1]);
	if (!mech) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Mechanism");
		return;
	}

	// Key template
	if ((info[3]->IsUndefined() || info[3]->IsNull())) {
		Nan::ThrowTypeError("Paramter 4 is REQUIERD and MUST be Object");
		MECHANISM_free(mech);
		return;
	}
	TEMPLATE* pTemplate = v2c_TEMPLATE(info[3]->ToObject());

	CK_OBJECT_HANDLE hDerivedKey;

	UNWRAP_PKCS11;

	CK_RV rv = __pkcs11->functionList->C_DeriveKey(hSession, mech, hBaseKey, pTemplate->items, pTemplate->size, &hDerivedKey);
	MECHANISM_free(mech);
	TEMPLATE_free(pTemplate);
	if (rv != CKR_OK) {
		THROW_PKCS11_ERROR(rv);
		return;
	}

	info.GetReturnValue().Set(Nan::New<Number>(hDerivedKey));
}

NAN_METHOD(PKCS11::C_SeedRandom) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Seed
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(seed, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_SeedRandom(hSession, (CK_BYTE_PTR)seed, seedLen));

	info.GetReturnValue().Set(info[1]);
}

NAN_METHOD(PKCS11::C_GenerateRandom) {
	CHECK_REQUIRED(0);
	CHECK_TYPE(0, Number);
	CK_SESSION_HANDLE hSession = info[0]->ToNumber()->Uint32Value();

	// Random data
	if (!node::Buffer::HasInstance(info[1])) {
		Nan::ThrowTypeError("Parameter 2 is REQUIRED and MUST be Buffer");
		return;
	}
	GET_BUFFER_ARGS(randomData, 1);

	UNWRAP_PKCS11;

	CHECK_PKCS11_RV(__pkcs11->functionList->C_GenerateRandom(hSession, (CK_BYTE_PTR)randomData, randomDataLen));

	info.GetReturnValue().Set(info[1]);
}