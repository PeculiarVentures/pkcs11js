#include "mech.h"

Mechanism::Mechanism() {
	New();
}

Mechanism::~Mechanism() {
}

void Mechanism::FromV8(Local<Value> v8Value) {
    Nan::HandleScope scope;
    
	try {
		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

        Local<Object> v8Object = Nan::To<v8::Object>(v8Value).ToLocalChecked();

        Local<Value> v8MechType = Nan::Get(v8Object, Nan::New(STR_MECHANISM).ToLocalChecked()).ToLocalChecked();
		if (!v8MechType->IsNumber()) {
			THROW_ERROR("Attribute 'mechanism' MUST be Number", NULL);
		}

        Local<Value> v8Parameter = Nan::Get(v8Object, Nan::New(STR_PARAMETER).ToLocalChecked()).ToLocalChecked();
		if (!(v8Parameter->IsUndefined() || v8Parameter->IsNull() || node::Buffer::HasInstance(v8Parameter) || v8Parameter->IsObject())) {
			THROW_ERROR("Attribute 'parameter' MUST be Null | Buffer | Object", NULL);
		}

		New();

		data.mechanism = Nan::To<uint32_t>(v8MechType).FromJust();
		if (!(v8Parameter->IsUndefined() || v8Parameter->IsNull())) {
            Local<Object> v8Param =  Nan::To<v8::Object>(v8Parameter).ToLocalChecked();
			if (!node::Buffer::HasInstance(v8Param)) {
                // Parameter is Object
                Local<Value> v8Type = Nan::Get(v8Param, Nan::New(STR_TYPE).ToLocalChecked()).ToLocalChecked();
				CK_ULONG type = v8Type->IsNumber() ? Nan::To<uint32_t>(v8Type).FromJust() : 0;
                switch (type) {
                    case CK_PARAMS_EC_DH: {
                        param = Scoped<ParamBase>(new ParamEcdh1);
                        break;
                    }
                    case CK_PARAMS_AES_CBC: {
                        param = Scoped<ParamBase>(new ParamAesCBC);
                        break;
                    }
                    case CK_PARAMS_AES_GCM: {
                        param = Scoped<ParamBase>(new ParamAesGCM);
                        break;
                    }
                    case CK_PARAMS_AES_GCM_v240: {
                        param = Scoped<ParamBase>(new ParamAesGCMv240);
                        break;
                    }
                    case CK_PARAMS_AES_CCM: {
                        param = Scoped<ParamBase>(new ParamAesCCM);
                        break;
                    }
                    case CK_PARAMS_RSA_OAEP: {
                        param = Scoped<ParamBase>(new ParamRsaOAEP);
                        break;
                    }
                    case CK_PARAMS_RSA_PSS: {
                        param = Scoped<ParamBase>(new ParamRsaPSS);
                        break;
                    }
                    default:
                        THROW_ERROR("Unknown type Mech param in use", NULL);
                }
			}
			else {
                // Parameter is buffer
                param = Scoped<ParamBase>(new ParamBuffer);
			}
            param->FromV8(v8Parameter);
            data.pParameter = param->Get();
            data.ulParameterLen = param->GetSize();
		}
	}
	CATCH_ERROR;
}

Local<Object> Mechanism::ToV8() {
    Nan::EscapableHandleScope scope;
    
	try {
		Local<Object> v8Mechanism = Nan::New<Object>();
		// Mechanism
        Nan::Set(v8Mechanism, Nan::New(STR_MECHANISM).ToLocalChecked(), Nan::New<Number>(data.mechanism));

		// Parameter
		if (data.pParameter) {
			Local<Object> v8Parameter = node::Buffer::Copy(Isolate::GetCurrent(), (char *)data.pParameter, data.ulParameterLen).ToLocalChecked();
            Nan::Set(v8Mechanism, Nan::New(STR_PARAMETER).ToLocalChecked(), v8Parameter);
		}
		else {
            Nan::Set(v8Mechanism, Nan::New(STR_PARAMETER).ToLocalChecked(), Nan::Null());
		}

		return scope.Escape(v8Mechanism);
	}
	CATCH_ERROR;
}

CK_MECHANISM_PTR Mechanism::New() {
	param = NULL;
	data = CK_MECHANISM();
	data.mechanism = 0;
	data.pParameter = NULL;
	data.ulParameterLen = 0;
	return Get();
}
