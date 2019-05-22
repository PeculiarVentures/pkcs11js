#include "param.h"

void ParamEcdh1::FromV8(Local<Value> v8Value) {
    Nan::HandleScope scope;
    
	try {
		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

        Local<Object> v8Params = Nan::To<v8::Object>(v8Value).ToLocalChecked();

		// Check data
		if (!check_param_number(v8Params, STR_KDF))
			THROW_ERROR("Attribute 'kdf' MUST be NUMBER", NULL);
		if (!(check_param_empty(v8Params, STR_SHARED_DATA) || check_param_buffer(v8Params, STR_SHARED_DATA)))
			THROW_ERROR("Attribute 'sharedData' MUST be NULL | Buffer", NULL);
		if (!check_param_buffer(v8Params, STR_PUBLIC_DATA))
			THROW_ERROR("Attribute 'publicData' MUST be Buffer", NULL);

		Free();
		Init();

        v8::Local<v8::Value> v8Kdf = Nan::Get(v8Params, Nan::New(STR_KDF).ToLocalChecked()).ToLocalChecked();
		param.kdf = Nan::To<uint32_t>(v8Kdf).FromJust();

		if (check_param_buffer(v8Params, STR_SHARED_DATA)) {
            v8::Local<v8::Value> v8SharedData = Nan::Get(v8Params, Nan::New(STR_SHARED_DATA).ToLocalChecked()).ToLocalChecked();
			GET_BUFFER_SMPL(sharedData, Nan::To<v8::Object>(v8SharedData).ToLocalChecked());
			param.pSharedData = (CK_BYTE_PTR)malloc(sharedDataLen * sizeof(CK_BYTE));
			memcpy(param.pSharedData, sharedData, sharedDataLen);
			param.ulSharedDataLen = (CK_ULONG) sharedDataLen;
		}

        v8::Local<v8::Value> v8PublicData =Nan::Get(v8Params, Nan::New(STR_PUBLIC_DATA).ToLocalChecked()).ToLocalChecked();
        GET_BUFFER_SMPL(publicData, Nan::To<v8::Object>(v8PublicData).ToLocalChecked());
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
