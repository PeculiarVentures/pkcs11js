#include "param.h"

void ParamRsaOAEP::FromV8(Local<Value> v8Value) {
	try {
		Nan::HandleScope();

		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Params = v8Value->ToObject();

		// Check data
		if (!check_param_number(v8Params, STR_MGF))
			THROW_ERROR("Attribute 'mgf' MUST be NUMBER", NULL);
		if (!check_param_number(v8Params, STR_SOURCE))
			THROW_ERROR("Attribute 'source' MUST be NUMBER", NULL);
		if (!check_param_number(v8Params, STR_HASH_ALG))
			THROW_ERROR("Attribute 'hashAlg' MUST be NUMBER", NULL);
		if (!(check_param_empty(v8Params, STR_SOURCE_DATA) || check_param_buffer(v8Params, STR_SOURCE_DATA)))
			THROW_ERROR("Attribute 'iv' MUST be NULL || BUFFER", NULL);

		Free();
		Init();

		param.source = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_SOURCE).ToLocalChecked())).ToLocalChecked()->Uint32Value();
		param.mgf= Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_MGF).ToLocalChecked())).ToLocalChecked()->Uint32Value();
		param.hashAlg = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_HASH_ALG).ToLocalChecked())).ToLocalChecked()->Uint32Value();

		if (!check_param_empty(v8Params, STR_SOURCE_DATA)) {
			GET_BUFFER_SMPL(buffer, v8Params->Get(Nan::New(STR_SOURCE_DATA).ToLocalChecked())->ToObject());
			param.pSourceData = (CK_BYTE_PTR)malloc(bufferLen * sizeof(CK_BYTE));
			memcpy(param.pSourceData, buffer, bufferLen);
			param.ulSourceDataLen = (CK_ULONG)bufferLen;
		}
	}
	CATCH_ERROR;
}

void ParamRsaOAEP::Init() {
	param = CK_RSA_PKCS_OAEP_PARAMS();
	param.hashAlg = 0;
	param.source= 0; // CKZ_DATA_SPECIFIED ???
	param.mgf= 0;
	param.pSourceData = NULL;
	param.ulSourceDataLen = 0;
}

void ParamRsaOAEP::Free() {
    if (param.pSourceData) {
        free(param.pSourceData);
        param.pSourceData = NULL;
    }
}

// PSS =================================================================================

void ParamRsaPSS::FromV8(Local<Value> v8Value) {
	try {
		Nan::HandleScope();

		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Params = v8Value->ToObject();

		// Check data
		if (!check_param_number(v8Params, STR_MGF))
			THROW_ERROR("Attribute 'mgf' MUST be NUMBER", NULL);
		if (!check_param_number(v8Params, STR_SALT_LEN))
			THROW_ERROR("Attribute 'saltLen' MUST be NUMBER", NULL);
		if (!check_param_number(v8Params, STR_HASH_ALG))
			THROW_ERROR("Attribute 'hashAlg' MUST be NUMBER", NULL);

		Free();
		Init();

		param.sLen = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_SALT_LEN).ToLocalChecked())).ToLocalChecked()->Uint32Value();
		param.mgf = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_MGF).ToLocalChecked())).ToLocalChecked()->Uint32Value();
		param.hashAlg = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_HASH_ALG).ToLocalChecked())).ToLocalChecked()->Uint32Value();

	}
	CATCH_ERROR;
}

void ParamRsaPSS::Init() {
	param = CK_RSA_PKCS_PSS_PARAMS();
	param.hashAlg = 0;
	param.mgf = 0;
	param.sLen = 0;
}

void ParamRsaPSS::Free() {
}
