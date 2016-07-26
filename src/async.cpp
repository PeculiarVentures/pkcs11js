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

void AsyncGenerateKeyPair::Execute() {
	try {
		keyPair = pkcs11->C_GenerateKeyPair(hSession, mech, publicKeyTemplate, privateKeyTemplate);
	}
	catch (Scoped<Error> e) {
		this->SetErrorMessage(e->ToString()->c_str());
	}
}

void AsyncGenerateKeyPair::HandleOKCallback() {
	Nan::HandleScope scope;

	Local<Object> v8KeyPair = Nan::New<Object>();
	v8KeyPair->Set(Nan::New(STR_PRIVATE_KEY).ToLocalChecked(), Nan::New<Number>(keyPair->privateKey));
	v8KeyPair->Set(Nan::New(STR_PUBLIC_KEY).ToLocalChecked(), Nan::New<Number>(keyPair->publicKey));

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8KeyPair
	};

	callback->Call(2, argv);
}
