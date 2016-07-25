#ifndef INCLUDE_H_ASYNC
#define INCLUDE_H_ASYNC

#include "pkcs11.h"

using namespace node;
using namespace v8;

class AsyncGenerateKey : public Nan::AsyncWorker {
public:
	AsyncGenerateKey(
		Nan::Callback *callback,
		CK_SESSION_HANDLE hSession,
		MECHANISM* mech,
		TEMPLATE* tmpl
		) : AsyncWorker(callback), hSession(hSession), mech(mech), tmpl(tmpl) {}
	~AsyncGenerateKey() {}

	void Execute();
	void HandleOKCallback();

protected:
	CK_SESSION_HANDLE hSession;
	MECHANISM* mech;
	TEMPLATE* tmpl;
	// Result
	CK_ULONG key;
};

#endif // INCLUDE_H_ASYNC