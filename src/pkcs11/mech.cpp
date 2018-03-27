#include "mech.h"

Mechanism::Mechanism() {
	New();
}

Mechanism::~Mechanism() {
}

void Mechanism::FromV8(Local<Value> v8Value) {
	try {
		Nan::HandleScope();

		if (!v8Value->IsObject()) {
			THROW_ERROR("Parameter 1 MUST be Object", NULL);
		}

		Local<Object> v8Object = v8Value->ToObject();

		Local<Value> v8MechType = v8Object->Get(Nan::New(STR_MECHANISM).ToLocalChecked());
		if (!v8MechType->IsNumber()) {
			THROW_ERROR("Attribute 'mechanism' MUST be Number", NULL);
		}

		Local<Value> v8Parameter = v8Object->Get(Nan::New(STR_PARAMETER).ToLocalChecked());
		if (!(v8Parameter->IsUndefined() || v8Parameter->IsNull() || node::Buffer::HasInstance(v8Parameter) || v8Parameter->IsObject())) {
			THROW_ERROR("Attribute 'parameter' MUST be Null | Buffer | Object", NULL);
		}

		New();

		data.mechanism = Nan::To<v8::Number>(v8MechType).ToLocalChecked()->Uint32Value();
		if (!(v8Parameter->IsUndefined() || v8Parameter->IsNull())) {
			Local<Object> v8Param = v8Parameter->ToObject();
			if (!node::Buffer::HasInstance(v8Param)) {
                // Parameter is Object
				Local<Object> v8Param = v8Parameter->ToObject();
				Local<Value> v8Type = v8Param->Get(Nan::New(STR_TYPE).ToLocalChecked());
				CK_ULONG type = v8Type->IsNumber() ? Nan::To<v8::Number>(v8Type).ToLocalChecked()->Uint32Value() : 0;
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
	try {
		Nan::HandleScope();

		Local<Object> v8Mechanism = Nan::New<Object>();
		// Mechanism
		v8Mechanism->Set(Nan::New(STR_MECHANISM).ToLocalChecked(), Nan::New<Number>(data.mechanism));

		// Parameter
		if (data.pParameter) {
			Local<Object> v8Parameter = node::Buffer::Copy(Isolate::GetCurrent(), (char *)data.pParameter, data.ulParameterLen).ToLocalChecked();
			v8Mechanism->Set(Nan::New(STR_PARAMETER).ToLocalChecked(), v8Parameter);
		}
		else {
			v8Mechanism->Set(Nan::New(STR_PARAMETER).ToLocalChecked(), Nan::Null());
		}

		return v8Mechanism;
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
