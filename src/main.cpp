#include <nan.h>
#include <node.h>

#include "pkcs11.h"

NAN_MODULE_INIT(init) {
	Nan::HandleScope scope;

	PKCS11::Init(target);
}

NODE_MODULE(pkcs11, init)