#include "param.h"

void ParamEcdh1::FromV8(Local<Value> v8Value) {
	try {
		Nan::HandleScope();

		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Params = v8Value->ToObject();

		// Check data
		if (!v8Params->Get(Nan::New(STR_KDF).ToLocalChecked())->IsNumber())
			THROW_ERROR("Attribute 'kdf' MUST be NUMBER", NULL);
		if (!(check_param_empty(v8Params, STR_SHARED_DATA) || check_param_buffer(v8Params, STR_SHARED_DATA)))
			THROW_ERROR("Attribute 'sharedData' MUST be NULL | Buffer", NULL);
		if (!check_param_buffer(v8Params, STR_PUBLIC_DATA))
			THROW_ERROR("Attribute 'publicData' MUST be Buffer", NULL);

		Free();
		Init();

		param.kdf = (CK_ULONG)Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_KDF).ToLocalChecked())).ToLocalChecked()->Uint32Value();

		if (check_param_buffer(v8Params, STR_SHARED_DATA)) {
			GET_BUFFER_SMPL(sharedData, v8Params->Get(Nan::New(STR_SHARED_DATA).ToLocalChecked())->ToObject());
			param.pSharedData = (CK_BYTE_PTR)malloc(sharedDataLen * sizeof(CK_BYTE));
			memcpy(param.pSharedData, sharedData, sharedDataLen);
			param.ulSharedDataLen = (CK_ULONG) sharedDataLen;
		}

		GET_BUFFER_SMPL(publicData, v8Params->Get(Nan::New(STR_PUBLIC_DATA).ToLocalChecked())->ToObject());
		param.pPublicData = (CK_BYTE_PTR)malloc(publicDataLen * sizeof(CK_BYTE));
		memcpy(param.pPublicData, publicData, publicDataLen);
		param.ulPublicDataLen = (CK_ULONG) publicDataLen;
	}
	CATCH_ERROR;
}

void ParamEcdh1::Init() {
	param = CK_ECDH1_DERIVE_PARAMS();
	param.kdf = CKD_NULL;
	param.pSharedData = NULL;
	param.ulSharedDataLen = 0;
	param.pPublicData = NULL;
	param.ulPublicDataLen = 0;
}

void ParamEcdh1::Free() {
    if (param.pSharedData) {
        free(param.pSharedData);
        param.pSharedData = NULL;
    }
    if (param.pPublicData) {
        free(param.pPublicData);
        param.pPublicData = NULL;
    }
}
