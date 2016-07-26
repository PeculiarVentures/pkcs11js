#include "./async.h"

void AsyncGenerateKey::Execute() {
	try {
		hKey =  pkcs11->C_GenerateKey(hSession, mech, tmpl);
	}
	catch (Scoped<Error> e) {
		this->SetErrorMessage(e->ToString()->c_str());
	}
}

void AsyncGenerateKey::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		Nan::New<Number>(hKey)
	};

	callback->Call(2, argv);
}
