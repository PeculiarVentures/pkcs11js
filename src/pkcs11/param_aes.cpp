#include "param.h"

// CBC ========================================================

void ParamAesCBC::FromV8(Local<Value> v8Value) {
	Nan::HandleScope scope;
    
    try {
		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Params =  Nan::To<v8::Object>(v8Value).ToLocalChecked();

		// Check data
		if (!check_param_buffer(v8Params, STR_IV))
			THROW_ERROR("Attribute 'iv' MUST be BUFFER", NULL);
		if (!(check_param_empty(v8Params, STR_DATA) || check_param_buffer(v8Params, STR_DATA)))
			THROW_ERROR("Attribute 'data' MUST be NULL | Buffer", NULL);
		
        Free();
		Init();

		// Iv
        v8::Local<v8::Value> v8Iv =Nan::Get(v8Params, Nan::New(STR_IV).ToLocalChecked()).ToLocalChecked();
        GET_BUFFER_SMPL(iv, Nan::To<v8::Object>(v8Iv).ToLocalChecked());
		memcpy(param.iv, iv, ivLen);

		// Data?
		if (!check_param_empty(v8Params, STR_DATA)) {
            v8::Local<v8::Value> v8Data = Nan::Get(v8Params, Nan::New(STR_DATA).ToLocalChecked()).ToLocalChecked();
            GET_BUFFER_SMPL(aesData, Nan::To<v8::Object>(v8Data).ToLocalChecked());
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
	Nan::HandleScope scope;
    
    try {
		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

        Local<Object> v8Params = Nan::To<v8::Object>(v8Value).ToLocalChecked();

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

        v8::Local<v8::Value> v8DataLen = Nan::Get(v8Params, Nan::New(STR_DATA_LEN).ToLocalChecked()).ToLocalChecked();
		param.ulDataLen = Nan::To<uint32_t>(v8DataLen).FromJust();
        v8::Local<v8::Value> v8MacLen = Nan::Get(v8Params, Nan::New(STR_MAC_LEN).ToLocalChecked()).ToLocalChecked();
		param.ulMACLen = Nan::To<uint32_t>(v8MacLen).FromJust();

		if (!check_param_empty(v8Params,STR_NONCE)) {
            v8::Local<v8::Value> v8Nonce = Nan::Get(v8Params, Nan::New(STR_NONCE).ToLocalChecked()).ToLocalChecked();
            GET_BUFFER_SMPL(nonce, Nan::To<v8::Object>(v8Nonce).ToLocalChecked());
			param.pNonce = (CK_BYTE_PTR)malloc(nonceLen * sizeof(CK_BYTE));
			memcpy(param.pNonce, nonce, nonceLen);
			param.ulNonceLen = (CK_ULONG)nonceLen;
		}

		if (!check_param_empty(v8Params, STR_AAD)) {
            v8::Local<v8::Value> v8Aad = Nan::Get(v8Params, Nan::New(STR_AAD).ToLocalChecked()).ToLocalChecked();
            GET_BUFFER_SMPL(aad, Nan::To<v8::Object>(v8Aad).ToLocalChecked());
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
    Nan::HandleScope scope;
    
    try {
        if (!v8Value->IsObject()) {
            THROW_ERROR("Parameter 1 MUST be Object", NULL);
        }
        
        Local<Object> v8Params = Nan::To<v8::Object>(v8Value).ToLocalChecked();
        
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
        
        v8::Local<v8::Value> v8TagBits = Nan::Get(v8Params, Nan::New(STR_TAG_BITS).ToLocalChecked()).ToLocalChecked();
        param.ulTagBits = Nan::To<uint32_t>(v8TagBits).FromJust();
        
        if (!check_param_empty(v8Params, STR_IV)) {
            v8::Local<v8::Value> v8Iv = Nan::Get(v8Params, Nan::New(STR_IV).ToLocalChecked()).ToLocalChecked();
            GET_BUFFER_SMPL(buffer, Nan::To<v8::Object>(v8Iv).ToLocalChecked());
            param.pIv = (CK_BYTE_PTR)malloc(bufferLen * sizeof(CK_BYTE));
            memcpy(param.pIv, buffer, bufferLen);
            param.ulIvLen = (CK_ULONG)bufferLen;
        }
        
        if (!check_param_empty(v8Params, STR_AAD)) {
            v8::Local<v8::Value> v8Aad = Nan::Get(v8Params, Nan::New(STR_AAD).ToLocalChecked()).ToLocalChecked();
            GET_BUFFER_SMPL(buffer, Nan::To<v8::Object>(v8Aad).ToLocalChecked());
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
    Nan::HandleScope scope;
    
	try {
		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Params = Nan::To<v8::Object>(v8Value).ToLocalChecked();

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

        v8::Local<v8::Value> v8IvBits = Nan::Get(v8Params, Nan::New(STR_IV_BITS).ToLocalChecked()).ToLocalChecked();
		param.ulIvBits = Nan::To<uint32_t>(v8IvBits).FromJust();
        v8::Local<v8::Value> v8TagBits = Nan::Get(v8Params, Nan::New(STR_TAG_BITS).ToLocalChecked()).ToLocalChecked();
		param.ulTagBits = Nan::To<uint32_t>(v8TagBits).FromJust();

		if (!check_param_empty(v8Params, STR_IV)) {
            v8::Local<v8::Value> v8Iv = Nan::Get(v8Params, Nan::New(STR_IV).ToLocalChecked()).ToLocalChecked();
			GET_BUFFER_SMPL(buffer, Nan::To<v8::Object>(v8Iv).ToLocalChecked());
			param.pIv = (CK_BYTE_PTR)malloc(bufferLen * sizeof(CK_BYTE));
			memcpy(param.pIv, buffer, bufferLen);
			param.ulIvLen = (CK_ULONG)bufferLen;
		}

		if (!check_param_empty(v8Params, STR_AAD)) {
            v8::Local<v8::Value> v8Aad = Nan::Get(v8Params, Nan::New(STR_AAD).ToLocalChecked()).ToLocalChecked();
            GET_BUFFER_SMPL(buffer, Nan::To<v8::Object>(v8Aad).ToLocalChecked());
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
