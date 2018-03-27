#include "param.h"

// CBC ========================================================

void ParamAesCBC::FromV8(Local<Value> v8Value) {
	try {
		Nan::HandleScope();

		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Params = v8Value->ToObject();

		// Check data
		if (!check_param_buffer(v8Params, STR_IV))
			THROW_ERROR("Attribute 'iv' MUST be BUFFER", NULL);
		if (!(check_param_empty(v8Params, STR_DATA) || check_param_buffer(v8Params, STR_DATA)))
			THROW_ERROR("Attribute 'data' MUST be NULL | Buffer", NULL);
		
        Free();
		Init();

		// Iv
		Local<Object> v8Iv = v8Params->Get(Nan::New(STR_IV).ToLocalChecked())->ToObject();
		memcpy(param.iv, node::Buffer::Data(v8Iv), node::Buffer::Length(v8Iv));

		// Data?
		if (!v8Params->Get(Nan::New(STR_DATA).ToLocalChecked())->IsUndefined()) {
			GET_BUFFER_SMPL(aesData, v8Params->Get(Nan::New(STR_DATA).ToLocalChecked())->ToObject());
			param.pData = (CK_BYTE_PTR)malloc(aesDataLen* sizeof(CK_BYTE));
			memcpy(param.pData, aesData, aesDataLen);
			param.length = (CK_ULONG)aesDataLen;
		}
	}
	CATCH_ERROR;
}

void ParamAesCBC::Init() {
	param = CK_AES_CBC_ENCRYPT_DATA_PARAMS();
	param.pData = NULL;
	param.length = 0;
}

void ParamAesCBC::Free() {
    if (param.pData) {
        free(param.pData);
        param.pData = NULL;
    }
}

// CCM ========================================================

void ParamAesCCM::FromV8(Local<Value> v8Value) {
	try {
		Nan::HandleScope();

		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Params = v8Value->ToObject();

		// Check data
		if (!check_param_number(v8Params, STR_DATA_LEN))
			THROW_ERROR("Attribute 'dataLen' MUST be NUMBER", NULL);
		if (!(check_param_empty(v8Params, STR_NONCE) || check_param_buffer(v8Params, STR_NONCE)))
			THROW_ERROR("Attribute 'nonce' MUST be NULL || BUFFER", NULL);
		if (!(check_param_empty(v8Params, STR_AAD) || check_param_buffer(v8Params, STR_AAD)))
			THROW_ERROR("Attribute 'aad' MUST be NULL || BUFFER", NULL);
		if (!check_param_number(v8Params, STR_MAC_LEN))
			THROW_ERROR("Attribute 'macLen' MUST be NUMBER", NULL);

		Free();
		Init();

		param.ulDataLen = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_DATA_LEN).ToLocalChecked())).ToLocalChecked()->Uint32Value();
		param.ulMACLen = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_MAC_LEN).ToLocalChecked())).ToLocalChecked()->Uint32Value();

		if (!check_param_empty(v8Params,STR_NONCE)) {
			GET_BUFFER_SMPL(nonce, v8Params->Get(Nan::New(STR_NONCE).ToLocalChecked())->ToObject());
			param.pNonce = (CK_BYTE_PTR)malloc(nonceLen * sizeof(CK_BYTE));
			memcpy(param.pNonce, nonce, nonceLen);
			param.ulNonceLen = (CK_ULONG)nonceLen;
		}

		if (!check_param_empty(v8Params, STR_AAD)) {
			GET_BUFFER_SMPL(aad, v8Params->Get(Nan::New(STR_AAD).ToLocalChecked())->ToObject());
			param.pAAD = (CK_BYTE_PTR)malloc(aadLen * sizeof(CK_BYTE));
			memcpy(param.pAAD, aad, aadLen);
			param.ulAADLen = (CK_ULONG)aadLen;
		}
	}
	CATCH_ERROR;
}

void ParamAesCCM::Init() {
	param = CK_AES_CCM_PARAMS();
	param.ulDataLen = 0;
	param.pNonce = NULL;
	param.ulNonceLen = 0;
	param.pAAD = NULL;
	param.ulAADLen = 0;
	param.ulMACLen = 0;
}

void ParamAesCCM::Free() {
    if (param.pNonce) {
        free(param.pNonce);
        param.pNonce = NULL;
    }
    if (param.pAAD) {
        free(param.pAAD);
        param.pAAD = NULL;
    }
    
}

// GCM ========================================================

// v2.30
void ParamAesGCM::FromV8(Local<Value> v8Value) {
    try {
        Nan::HandleScope();
        
        if (!v8Value->IsObject()) {
            THROW_ERROR("Parameter 1 MUST be Object", NULL);
        }
        
        Local<Object> v8Params = v8Value->ToObject();
        
        // Check data
        if (!check_param_number(v8Params, STR_TAG_BITS))
            THROW_ERROR("Attribute 'tagBits' MUST be NUMBER", NULL);
        if (!check_param_number(v8Params, STR_IV_BITS))
            THROW_ERROR("Attribute 'ivBits' MUST be NUMBER", NULL);
        if (!(check_param_empty(v8Params, STR_IV) || check_param_buffer(v8Params, STR_IV)))
            THROW_ERROR("Attribute 'iv' MUST be NULL || BUFFER", NULL);
        if (!(check_param_empty(v8Params, STR_AAD) || check_param_buffer(v8Params, STR_AAD)))
            THROW_ERROR("Attribute 'aad' MUST be NULL || BUFFER", NULL);
        
        Free();
        Init();
        
        param.ulTagBits = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_TAG_BITS).ToLocalChecked())).ToLocalChecked()->Uint32Value();
        
        if (!check_param_empty(v8Params, STR_IV)) {
            GET_BUFFER_SMPL(buffer, v8Params->Get(Nan::New(STR_IV).ToLocalChecked())->ToObject());
            param.pIv = (CK_BYTE_PTR)malloc(bufferLen * sizeof(CK_BYTE));
            memcpy(param.pIv, buffer, bufferLen);
            param.ulIvLen = (CK_ULONG)bufferLen;
        }
        
        if (!check_param_empty(v8Params, STR_AAD)) {
            GET_BUFFER_SMPL(buffer, v8Params->Get(Nan::New(STR_AAD).ToLocalChecked())->ToObject());
            param.pAAD = (CK_BYTE_PTR)malloc(bufferLen * sizeof(CK_BYTE));
            memcpy(param.pAAD, buffer, bufferLen);
            param.ulAADLen = (CK_ULONG)bufferLen;
        }
    }
    CATCH_ERROR;
}

void ParamAesGCM::Init() {
    param = CK_AES_GCM_PARAMS();
    param.pAAD = NULL;
    param.ulAADLen = 0;
    param.pIv = NULL;
    param.ulIvLen = 0;
    param.ulTagBits = 0;
}

void ParamAesGCM::Free() {
    if (param.pIv) {
        free(param.pIv);
        param.pIv = NULL;
    }
    if (param.pAAD) {
        free(param.pAAD);
        param.pAAD = NULL;
    }
}

// v2.30

void ParamAesGCMv240::FromV8(Local<Value> v8Value) {
	try {
		Nan::HandleScope();

		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Params = v8Value->ToObject();

		// Check data
		if (!check_param_number(v8Params, STR_TAG_BITS))
			THROW_ERROR("Attribute 'tagBits' MUST be NUMBER", NULL);
		if (!check_param_number(v8Params, STR_IV_BITS))
			THROW_ERROR("Attribute 'ivBits' MUST be NUMBER", NULL);
		if (!(check_param_empty(v8Params, STR_IV) || check_param_buffer(v8Params, STR_IV)))
			THROW_ERROR("Attribute 'iv' MUST be NULL || BUFFER", NULL);
		if (!(check_param_empty(v8Params, STR_AAD) || check_param_buffer(v8Params, STR_AAD)))
			THROW_ERROR("Attribute 'aad' MUST be NULL || BUFFER", NULL);

		Free();
		Init();

		param.ulIvBits = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_IV_BITS).ToLocalChecked())).ToLocalChecked()->Uint32Value();
		param.ulTagBits = Nan::To<v8::Number>(v8Params->Get(Nan::New(STR_TAG_BITS).ToLocalChecked())).ToLocalChecked()->Uint32Value();

		if (!check_param_empty(v8Params, STR_IV)) {
			GET_BUFFER_SMPL(buffer, v8Params->Get(Nan::New(STR_IV).ToLocalChecked())->ToObject());
			param.pIv = (CK_BYTE_PTR)malloc(bufferLen * sizeof(CK_BYTE));
			memcpy(param.pIv, buffer, bufferLen);
			param.ulIvLen = (CK_ULONG)bufferLen;
		}

		if (!check_param_empty(v8Params, STR_AAD)) {
			GET_BUFFER_SMPL(buffer, v8Params->Get(Nan::New(STR_AAD).ToLocalChecked())->ToObject());
			param.pAAD = (CK_BYTE_PTR)malloc(bufferLen * sizeof(CK_BYTE));
			memcpy(param.pAAD, buffer, bufferLen);
			param.ulAADLen = (CK_ULONG)bufferLen;
		}
	}
	CATCH_ERROR;
}

void ParamAesGCMv240::Init() {
	param = CK_AES_GCM_240_PARAMS();
	param.pAAD = NULL;
	param.ulAADLen = 0;
	param.pIv = NULL;
	param.ulIvLen = 0;
	param.ulIvBits = 0;
	param.ulTagBits = 0;
}

void ParamAesGCMv240::Free() {
    if (param.pIv) {
        free(param.pIv);
        param.pIv = NULL;
    }
    if (param.pAAD) {
        free(param.pAAD);
        param.pAAD = NULL;
    }
}
