#ifndef INCLUDE_H_ASYNC
#define INCLUDE_H_ASYNC

#include "pkcs11/pkcs11.h"

using namespace node;
using namespace v8;

class AsyncGenerateKey : public Nan::AsyncWorker {
public:
	AsyncGenerateKey(
		Nan::Callback *callback,
		Scoped<PKCS11> pkcs11,
		CK_SESSION_HANDLE hSession,
		Scoped<Mechanism> mech,
		Scoped<Attributes> tmpl
		) : AsyncWorker(callback), pkcs11(pkcs11), hSession(hSession), mech(mech), tmpl(tmpl) {}
	~AsyncGenerateKey() {}

	void Execute();
	void HandleOKCallback();

protected:
	CK_SESSION_HANDLE hSession;
	Scoped<PKCS11> pkcs11;
	Scoped<Mechanism> mech;
	Scoped<Attributes> tmpl;
	// Result
	CK_OBJECT_HANDLE hKey;
};

class AsyncGenerateKeyPair : public Nan::AsyncWorker {
public:
	AsyncGenerateKeyPair(
		Nan::Callback *callback,
		Scoped<PKCS11> pkcs11,
		CK_SESSION_HANDLE hSession,
		Scoped<Mechanism> mech,
		Scoped<Attributes> publicKeyTemplate,
		Scoped<Attributes> privateKeyTemplate
	) : AsyncWorker(callback), pkcs11(pkcs11), hSession(hSession), mech(mech), publicKeyTemplate(publicKeyTemplate), privateKeyTemplate(privateKeyTemplate) {}
	~AsyncGenerateKeyPair() {}

	void Execute();
	void HandleOKCallback();

protected:
	CK_SESSION_HANDLE hSession;
	Scoped<PKCS11> pkcs11;
	Scoped<Mechanism> mech;
	Scoped<Attributes> publicKeyTemplate;
	Scoped<Attributes> privateKeyTemplate;
	// Result
	Scoped<KEY_PAIR> keyPair;
};

#endif // INCLUDE_H_ASYNC