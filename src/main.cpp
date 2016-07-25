#include <nan.h>
#include <node.h>

#include "node.h"

NAN_MODULE_INIT(init) {
	Nan::HandleScope scope;

	WPKCS11::Init(target);
}

NODE_MODULE(pkcs11, init)