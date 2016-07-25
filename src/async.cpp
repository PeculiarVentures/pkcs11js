#include "./async.h"

void AsyncGenerateKey::Execute() {
	try {
		key = ScopedAES::generate(keySize);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncGenerateKey::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WAes::NewInstance();
	WAes *wkey = WAes::Unwrap<WAes>(v8Key);
	wkey->data = this->key;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv);
}
