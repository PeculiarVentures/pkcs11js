#include "mech.h"
#include "param_ecdh.h"

Mechanism::Mechanism() {
	New();
}

Mechanism::~Mechanism() {
	Free();
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

		Free();
		New();

		data.mechanism = v8MechType->ToNumber()->Uint32Value();
		if (!(v8Parameter->IsUndefined() || v8Parameter->IsNull())) {
			// Buffer
			switch (data.mechanism) {
				case CKM_ECDH1_DERIVE: {
					ParamEcdh1* p = new ParamEcdh1();
					this->param = p;
					p->FromV8(v8Parameter);
					data.pParameter = p->Get();
					data.ulParameterLen = sizeof(*p->Get());
					break;
				}
			default:
				GET_BUFFER_SMPL(buf, v8Parameter->ToObject());
				data.pParameter = (char*)malloc(bufLen);
				memcpy(data.pParameter, buf, bufLen);
				data.ulParameterLen = bufLen;
			}
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

void Mechanism::Free() {
	if (&data && data.pParameter && !param) {
		free(data.pParameter);
	}
	if (param) {
		delete(param);
	}
}