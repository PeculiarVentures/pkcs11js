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
	Scoped<PKCS11> pkcs11;
	CK_SESSION_HANDLE hSession;
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
	Scoped<PKCS11> pkcs11;
	CK_SESSION_HANDLE hSession;
	Scoped<Mechanism> mech;
	Scoped<Attributes> publicKeyTemplate;
	Scoped<Attributes> privateKeyTemplate;
	// Result
	Scoped<KEY_PAIR> keyPair;
};

#define ASYNC_CRYPTO_DIGEST 0
#define ASYNC_CRYPTO_ENCRYPT 1
#define ASYNC_CRYPTO_DECRYPT 2
#define ASYNC_CRYPTO_SIGN 3
#define ASYNC_CRYPTO_VERIFY 4

class AsyncCrypto : public Nan::AsyncWorker {
public:
	AsyncCrypto(
		Nan::Callback *callback,
		Scoped<PKCS11> pkcs11,
		int type,
		CK_SESSION_HANDLE hSession,
		Scoped<string> input,
		Scoped<string> output
	) : AsyncWorker(callback), pkcs11(pkcs11), type(type), hSession(hSession), input(input), output(output) {}
	~AsyncCrypto() {}

	void Execute();
	void HandleOKCallback();

protected:
	Scoped<PKCS11> pkcs11;
	int type;
	CK_SESSION_HANDLE hSession;
	Scoped<string> input;
	Scoped<string> output;
	// Result
	Scoped<string> result;
};

#endif // INCLUDE_H_ASYNC