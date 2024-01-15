#include "common.h"

#define DEFINE_EXECUTE_WORKER(WorkerType)       \
  static void Execute(napi_env env, void *data) \
  {                                             \
    static_cast<WorkerType *>(data)->Execute(); \
  }

#define DEFINE_COMPLETE_WORKER(WorkerType)                               \
  static void CompleteWork(napi_env env, napi_status status, void *data) \
  {                                                                      \
    WorkerType *work = static_cast<WorkerType *>(data);                  \
    work->Complete(env);                                                 \
    napi_delete_async_work(env, work->work);                             \
    delete work;                                                         \
  }

class BaseWorker
{
public:
  napi_async_work work;
  napi_deferred deferred;
  napi_ref callback;
  CK_RV rv;

  BaseWorker(napi_env env, napi_value callback)
  {
    napi_create_reference(env, callback, 1, &this->callback);
  }

  virtual ~BaseWorker() {}

  virtual void Execute() = 0;
  virtual napi_value CreateResult(napi_env env) = 0;

  void CreateAndQueue(napi_env env, const char *name, napi_async_execute_callback execute, napi_async_complete_callback complete)
  {
    napi_value resource_name;
    napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resource_name);
    napi_create_async_work(env, nullptr, resource_name, execute, complete, this, &this->work);
    napi_queue_async_work(env, this->work);
  }

  virtual void Complete(napi_env env) final
  {
    napi_value callback;
    napi_get_reference_value(env, this->callback, &callback);
    napi_value global;
    napi_get_global(env, &global);
    napi_value argv[2];

    if (this->rv == CKR_OK)
    {
      argv[0] = CreateNull(env);
      argv[1] = CreateResult(env);
    }
    else
    {
      argv[0] = CreateError(env);
      argv[1] = CreateNull(env);
    }

    napi_call_function(env, global, callback, 2, argv, nullptr);
    napi_delete_reference(env, this->callback);
  }

private:
  napi_value CreateNull(napi_env env)
  {
    napi_value nullValue;
    napi_get_null(env, &nullValue);
    return nullValue;
  }

  napi_value CreateError(napi_env env)
  {
    const char *error_name = get_error_name(this->rv);
    char error_message[100];
    snprintf(error_message, sizeof(error_message), "%s:%lu", error_name, this->rv);
    napi_value errorMessage;
    napi_create_string_utf8(env, error_message, NAPI_AUTO_LENGTH, &errorMessage);
    napi_value error;
    napi_create_error(env, nullptr, errorMessage, &error);
    return error;
  }
};

class Worker : public BaseWorker
{
public:
  const CK_C_Encrypt function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_BYTE_PTR data;
  const CK_ULONG dataLength;
  CK_BYTE_PTR out;
  CK_ULONG outLength;

  Worker(
      napi_env env,
      napi_value callback,
      CK_C_Encrypt function,
      CK_SESSION_HANDLE sessionHandle,
      CK_BYTE_PTR data, CK_ULONG dataLength,
      CK_BYTE_PTR out, CK_ULONG outLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), data(data), dataLength(dataLength), out(out), outLength(outLength)
  {
    CreateAndQueue(env, "Worker", Worker::Execute, Worker::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(this->sessionHandle, this->data, this->dataLength, this->out, &this->outLength);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value outLength;
    napi_create_uint32(env, this->outLength, &outLength);
    return outLength;
  }

  DEFINE_EXECUTE_WORKER(Worker)
  DEFINE_COMPLETE_WORKER(Worker)
};

class Worker2 : public BaseWorker
{
public:
  const CK_C_DigestFinal function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_BYTE_PTR out;
  CK_ULONG outLength;

  Worker2(
      napi_env env,
      napi_value callback,
      CK_C_DigestFinal function,
      CK_SESSION_HANDLE sessionHandle,
      CK_BYTE_PTR out, CK_ULONG outLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), out(out), outLength(outLength)
  {
    CreateAndQueue(env, "Worker2", Worker2::Execute, Worker2::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(this->sessionHandle, this->out, &this->outLength);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value outLength;
    napi_create_uint32(env, this->outLength, &outLength);
    return outLength;
  }

  DEFINE_EXECUTE_WORKER(Worker2)
  DEFINE_COMPLETE_WORKER(Worker2)
};

class WorkerVerify : public BaseWorker
{
public:
  const CK_C_Verify function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_BYTE_PTR data;
  const CK_ULONG dataLength;
  CK_BYTE_PTR signature;
  const CK_ULONG signatureLength;

  WorkerVerify(
      napi_env env,
      napi_value callback,
      CK_C_Verify function,
      CK_SESSION_HANDLE sessionHandle,
      CK_BYTE_PTR data, CK_ULONG dataLength,
      CK_BYTE_PTR signature, CK_ULONG signatureLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), data(data), dataLength(dataLength), signature(signature), signatureLength(signatureLength)
  {
    CreateAndQueue(env, "WorkerVerify", WorkerVerify::Execute, WorkerVerify::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(this->sessionHandle, this->data, this->dataLength, this->signature, this->signatureLength);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value result;
    napi_get_boolean(env, this->rv == CKR_OK, &result);
    return result;
  }

  DEFINE_EXECUTE_WORKER(WorkerVerify)
  DEFINE_COMPLETE_WORKER(WorkerVerify)
};

class WorkerVerifyFinal : public BaseWorker
{
public:
  const CK_C_VerifyFinal function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_BYTE_PTR signature;
  const CK_ULONG signatureLength;

  WorkerVerifyFinal(
      napi_env env,
      napi_value callback,
      CK_C_VerifyFinal function,
      CK_SESSION_HANDLE sessionHandle,
      CK_BYTE_PTR signature, CK_ULONG signatureLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), signature(signature), signatureLength(signatureLength)
  {
    CreateAndQueue(env, "WorkerVerifyFinal", WorkerVerifyFinal::Execute, WorkerVerifyFinal::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(this->sessionHandle, this->signature, this->signatureLength);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value result;
    napi_get_boolean(env, this->rv == CKR_OK, &result);
    return result;
  }

  DEFINE_EXECUTE_WORKER(WorkerVerifyFinal)
  DEFINE_COMPLETE_WORKER(WorkerVerifyFinal)
};

class WorkerGenerateKey : public BaseWorker
{
public:
  const CK_C_GenerateKey function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_ATTRIBUTE_PTR attributes;
  CK_ULONG attributesLength;
  CK_OBJECT_HANDLE keyHandle;

  WorkerGenerateKey(
      napi_env env,
      napi_value callback,
      CK_C_GenerateKey function,
      CK_SESSION_HANDLE sessionHandle,
      CK_MECHANISM_PTR mechanism,
      CK_ATTRIBUTE_PTR attributes,
      CK_ULONG attributesLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), mechanism(mechanism), attributes(attributes), attributesLength(attributesLength)
  {
    CreateAndQueue(env, "WorkerGenerateKey", WorkerGenerateKey::Execute, WorkerGenerateKey::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(this->sessionHandle, this->mechanism, this->attributes, this->attributesLength, &this->keyHandle);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value keyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &this->keyHandle, nullptr, &keyHandle);
    return keyHandle;
  }

  DEFINE_EXECUTE_WORKER(WorkerGenerateKey)
  DEFINE_COMPLETE_WORKER(WorkerGenerateKey)
};

class WorkerGenerateKeyPair : public BaseWorker
{
public:
  const CK_C_GenerateKeyPair function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_ATTRIBUTE_PTR publicKeyAttributes;
  CK_ULONG publicKeyAttributesLength;
  CK_ATTRIBUTE_PTR privateKeyAttributes;
  CK_ULONG privateKeyAttributesLength;
  CK_OBJECT_HANDLE publicKeyHandle;
  CK_OBJECT_HANDLE privateKeyHandle;

  WorkerGenerateKeyPair(
      napi_env env,
      napi_value callback,
      CK_C_GenerateKeyPair function,
      CK_SESSION_HANDLE sessionHandle,
      CK_MECHANISM_PTR mechanism,
      CK_ATTRIBUTE_PTR publicKeyAttributes,
      CK_ULONG publicKeyAttributesLength,
      CK_ATTRIBUTE_PTR privateKeyAttributes,
      CK_ULONG privateKeyAttributesLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), mechanism(mechanism), publicKeyAttributes(publicKeyAttributes), publicKeyAttributesLength(publicKeyAttributesLength), privateKeyAttributes(privateKeyAttributes), privateKeyAttributesLength(privateKeyAttributesLength)
  {
    CreateAndQueue(env, "WorkerGenerateKeyPair", WorkerGenerateKeyPair::Execute, WorkerGenerateKeyPair::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(
        this->sessionHandle,
        this->mechanism,
        this->publicKeyAttributes, this->publicKeyAttributesLength,
        this->privateKeyAttributes, this->privateKeyAttributesLength,
        &this->publicKeyHandle,
        &this->privateKeyHandle);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value result;
    napi_create_object(env, &result);

    napi_value publicKeyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &this->publicKeyHandle, nullptr, &publicKeyHandle);
    napi_set_named_property(env, result, "publicKey", publicKeyHandle);

    napi_value privateKeyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &this->privateKeyHandle, nullptr, &privateKeyHandle);
    napi_set_named_property(env, result, "privateKey", privateKeyHandle);

    return result;
  }

  DEFINE_EXECUTE_WORKER(WorkerGenerateKeyPair)
  DEFINE_COMPLETE_WORKER(WorkerGenerateKeyPair)
};

class WorkerDeriveKey : public BaseWorker
{
public:
  const CK_C_DeriveKey function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_OBJECT_HANDLE baseKeyHandle;
  CK_ATTRIBUTE_PTR attributes;
  CK_ULONG attributesLength;
  CK_OBJECT_HANDLE keyHandle;

  WorkerDeriveKey(
      napi_env env,
      napi_value callback,
      CK_C_DeriveKey function,
      CK_SESSION_HANDLE sessionHandle,
      CK_MECHANISM_PTR mechanism,
      CK_OBJECT_HANDLE baseKeyHandle,
      CK_ATTRIBUTE_PTR attributes,
      CK_ULONG attributesLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), mechanism(mechanism), baseKeyHandle(baseKeyHandle), attributes(attributes), attributesLength(attributesLength)
  {
    CreateAndQueue(env, "WorkerDeriveKey", WorkerDeriveKey::Execute, WorkerDeriveKey::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(
        this->sessionHandle,
        this->mechanism,
        this->baseKeyHandle,
        this->attributes, this->attributesLength,
        &this->keyHandle);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value keyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &this->keyHandle, nullptr, &keyHandle);
    return keyHandle;
  }

  DEFINE_EXECUTE_WORKER(WorkerDeriveKey)
  DEFINE_COMPLETE_WORKER(WorkerDeriveKey)
};

class WorkerWrapKey : public BaseWorker
{
public:
  const CK_C_WrapKey function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_OBJECT_HANDLE wrappingKeyHandle;
  CK_OBJECT_HANDLE keyHandle;
  CK_BYTE_PTR wrappedKey;
  CK_ULONG wrappedKeyLength;

  WorkerWrapKey(
      napi_env env,
      napi_value callback,
      CK_C_WrapKey function,
      CK_SESSION_HANDLE sessionHandle,
      CK_MECHANISM_PTR mechanism,
      CK_OBJECT_HANDLE wrappingKeyHandle,
      CK_OBJECT_HANDLE keyHandle,
      CK_BYTE_PTR wrappedKey,
      CK_ULONG wrappedKeyLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), mechanism(mechanism), wrappingKeyHandle(wrappingKeyHandle), keyHandle(keyHandle), wrappedKey(wrappedKey), wrappedKeyLength(wrappedKeyLength)
  {
    CreateAndQueue(env, "WorkerWrapKey", WorkerWrapKey::Execute, WorkerWrapKey::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(
        this->sessionHandle,
        this->mechanism,
        this->wrappingKeyHandle,
        this->keyHandle,
        this->wrappedKey,
        &this->wrappedKeyLength);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value wrappedKeyLength;
    napi_create_uint32(env, this->wrappedKeyLength, &wrappedKeyLength);
    return wrappedKeyLength;
  }

  DEFINE_EXECUTE_WORKER(WorkerWrapKey)
  DEFINE_COMPLETE_WORKER(WorkerWrapKey)
};

class WorkerUnwrapKey : public BaseWorker
{
public:
  const CK_C_UnwrapKey function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_OBJECT_HANDLE unwrappingKeyHandle;
  CK_BYTE_PTR wrappedKey;
  CK_ULONG wrappedKeyLength;
  CK_ATTRIBUTE_PTR attributes;
  CK_ULONG attributesLength;
  CK_OBJECT_HANDLE keyHandle;

  WorkerUnwrapKey(
      napi_env env,
      napi_value callback,
      CK_C_UnwrapKey function,
      CK_SESSION_HANDLE sessionHandle,
      CK_MECHANISM_PTR mechanism,
      CK_OBJECT_HANDLE unwrappingKeyHandle,
      CK_BYTE_PTR wrappedKey,
      CK_ULONG wrappedKeyLength,
      CK_ATTRIBUTE_PTR attributes,
      CK_ULONG attributesLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), mechanism(mechanism), unwrappingKeyHandle(unwrappingKeyHandle), wrappedKey(wrappedKey), wrappedKeyLength(wrappedKeyLength), attributes(attributes), attributesLength(attributesLength)
  {
    CreateAndQueue(env, "WorkerUnwrapKey", WorkerUnwrapKey::Execute, WorkerUnwrapKey::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(
        this->sessionHandle,
        this->mechanism,
        this->unwrappingKeyHandle,
        this->wrappedKey,
        this->wrappedKeyLength,
        this->attributes, this->attributesLength,
        &this->keyHandle);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value keyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &this->keyHandle, nullptr, &keyHandle);
    return keyHandle;
  }

  DEFINE_EXECUTE_WORKER(WorkerUnwrapKey)
  DEFINE_COMPLETE_WORKER(WorkerUnwrapKey)
};

class WorkerDualOperation : public BaseWorker
{
public:
  const CK_C_DigestEncryptUpdate function;
  const CK_SESSION_HANDLE sessionHandle;
  CK_BYTE_PTR data;
  const CK_ULONG dataLength;
  CK_BYTE_PTR out;
  CK_ULONG outLength;

  WorkerDualOperation(
      napi_env env,
      napi_value callback,
      CK_C_DigestEncryptUpdate function,
      CK_SESSION_HANDLE sessionHandle,
      CK_BYTE_PTR data, CK_ULONG dataLength,
      CK_BYTE_PTR out, CK_ULONG outLength)
      : BaseWorker(env, callback), function(function), sessionHandle(sessionHandle), data(data), dataLength(dataLength), out(out), outLength(outLength)
  {
    CreateAndQueue(env, "WorkerDualOperation", WorkerDualOperation::Execute, WorkerDualOperation::CompleteWork);
  }

  void Execute() override
  {
    this->rv = this->function(this->sessionHandle, this->data, this->dataLength, this->out, &this->outLength);
  }

  napi_value CreateResult(napi_env env) override
  {
    napi_value outLength;
    napi_create_uint32(env, this->outLength, &outLength);
    return outLength;
  }

  DEFINE_EXECUTE_WORKER(WorkerDualOperation)
  DEFINE_COMPLETE_WORKER(WorkerDualOperation)
};
