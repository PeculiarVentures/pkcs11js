#include "common.h"

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

  static void Execute(napi_env env, void *data)
  {
    static_cast<Worker *>(data)->Execute();
  }

  static void CompleteWork(napi_env env, napi_status status, void *data)
  {
    Worker *work = static_cast<Worker *>(data);
    work->Complete(env);
    napi_delete_async_work(env, work->work);
    delete work;
  }
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

  static void Execute(napi_env env, void *data)
  {
    static_cast<Worker2 *>(data)->Execute();
  }

  static void CompleteWork(napi_env env, napi_status status, void *data)
  {
    Worker2 *work = static_cast<Worker2 *>(data);
    work->Complete(env);
    napi_delete_async_work(env, work->work);
    delete work;
  }
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

  static void Execute(napi_env env, void *data)
  {
    static_cast<WorkerVerify *>(data)->Execute();
  }

  static void CompleteWork(napi_env env, napi_status status, void *data)
  {
    WorkerVerify *work = static_cast<WorkerVerify *>(data);
    work->Complete(env);
    napi_delete_async_work(env, work->work);
    delete work;
  }
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

  static void Execute(napi_env env, void *data)
  {
    static_cast<WorkerVerifyFinal *>(data)->Execute();
  }

  static void CompleteWork(napi_env env, napi_status status, void *data)
  {
    WorkerVerifyFinal *work = static_cast<WorkerVerifyFinal *>(data);
    work->Complete(env);
    napi_delete_async_work(env, work->work);
    delete work;
  }
};

struct WorkerGenerateKey
{
  napi_async_work work;
  napi_deferred deferred;
  napi_ref callback;
  CK_C_GenerateKey function;
  CK_RV rv;
  CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_ATTRIBUTE_PTR attributes;
  CK_ULONG attributesLength;
  CK_OBJECT_HANDLE keyHandle;
};

void WorkerGenerateKeyExecute(napi_env env, void *data)
{
  WorkerGenerateKey *work = static_cast<WorkerGenerateKey *>(data);

  work->rv = work->function(work->sessionHandle, work->mechanism, work->attributes, work->attributesLength, &work->keyHandle);
}

void WorkerGenerateKeyComplete(napi_env env, napi_status status, void *data)
{
  WorkerGenerateKey *work = static_cast<WorkerGenerateKey *>(data);
  MechanismWrapper mechanism(work->mechanism, true);
  AttributesWrapper attributes(work->attributes, work->attributesLength, true);

  napi_value callback;
  napi_get_reference_value(env, work->callback, &callback);
  napi_value global;
  napi_get_global(env, &global);
  napi_value argv[2];
  napi_value nullValue;
  napi_get_null(env, &nullValue);

  if (work->rv == CKR_OK)
  {
    napi_value keyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &work->keyHandle, nullptr, &keyHandle);

    argv[0] = nullValue;
    argv[1] = keyHandle;
  }
  else
  {
    const char *error_name = get_error_name(work->rv);
    char error_message[100];
    snprintf(error_message, sizeof(error_message), "%s:%lu", error_name, work->rv);
    napi_value errorMessage;
    napi_create_string_utf8(env, error_message, NAPI_AUTO_LENGTH, &errorMessage);
    napi_value error;
    napi_create_error(env, nullptr, errorMessage, &error);

    argv[0] = error;
    argv[1] = nullValue;
  }

  napi_call_function(env, global, callback, 2, argv, nullptr);
  napi_delete_reference(env, work->callback);

  napi_delete_async_work(env, work->work);
  delete work;
}

WorkerGenerateKey *newWorkerGenerateKey(napi_env env, CK_C_GenerateKey function, napi_value callback, CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributesLength)
{
  WorkerGenerateKey *work = new WorkerGenerateKey;
  work->function = function;
  work->rv = CKR_OK;
  work->sessionHandle = sessionHandle;
  work->mechanism = mechanism;
  work->attributes = attributes;
  work->attributesLength = attributesLength;
  napi_create_reference(env, callback, 1, &work->callback);

  napi_value resource_name;
  napi_create_string_utf8(env, "WorkerGenerateKey", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_async_work(env, nullptr, resource_name, WorkerGenerateKeyExecute, WorkerGenerateKeyComplete, work, &work->work);
  napi_queue_async_work(env, work->work);

  return work;
}

struct WorkerGenerateKeyPair
{
  napi_async_work work;
  napi_deferred deferred;
  napi_ref callback;
  CK_C_GenerateKeyPair function;
  CK_RV rv;
  CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_ATTRIBUTE_PTR publicKeyAttributes;
  CK_ULONG publicKeyAttributesLength;
  CK_ATTRIBUTE_PTR privateKeyAttributes;
  CK_ULONG privateKeyAttributesLength;
  CK_OBJECT_HANDLE publicKeyHandle;
  CK_OBJECT_HANDLE privateKeyHandle;
};

void WorkerGenerateKeyPairExecute(napi_env env, void *data)
{
  WorkerGenerateKeyPair *work = static_cast<WorkerGenerateKeyPair *>(data);

  work->rv = work->function(
      work->sessionHandle,
      work->mechanism,
      work->publicKeyAttributes, work->publicKeyAttributesLength,
      work->privateKeyAttributes, work->privateKeyAttributesLength,
      &work->publicKeyHandle,
      &work->privateKeyHandle);
}

void WorkerGenerateKeyPairComplete(napi_env env, napi_status status, void *data)
{
  WorkerGenerateKeyPair *work = static_cast<WorkerGenerateKeyPair *>(data);
  MechanismWrapper mechanism(work->mechanism, true);
  AttributesWrapper publicKeyAttributes(work->publicKeyAttributes, work->publicKeyAttributesLength, true);
  AttributesWrapper privateKeyAttributes(work->privateKeyAttributes, work->privateKeyAttributesLength, true);

  napi_value callback;
  napi_get_reference_value(env, work->callback, &callback);
  napi_value global;
  napi_get_global(env, &global);
  napi_value argv[2];
  napi_value nullValue;
  napi_get_null(env, &nullValue);

  if (work->rv == CKR_OK)
  {
    napi_value result;
    napi_create_object(env, &result);

    napi_value publicKeyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &work->publicKeyHandle, nullptr, &publicKeyHandle);
    napi_set_named_property(env, result, "publicKey", publicKeyHandle);

    napi_value privateKeyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &work->privateKeyHandle, nullptr, &privateKeyHandle);
    napi_set_named_property(env, result, "privateKey", privateKeyHandle);

    argv[0] = nullValue;
    argv[1] = result;
  }
  else
  {
    const char *error_name = get_error_name(work->rv);
    char error_message[100];
    snprintf(error_message, sizeof(error_message), "%s:%lu", error_name, work->rv);
    napi_value errorMessage;
    napi_create_string_utf8(env, error_message, NAPI_AUTO_LENGTH, &errorMessage);
    napi_value error;
    napi_create_error(env, nullptr, errorMessage, &error);

    argv[0] = error;
    argv[1] = nullValue;
  }

  napi_call_function(env, global, callback, 2, argv, nullptr);
  napi_delete_reference(env, work->callback);

  napi_delete_async_work(env, work->work);
  delete work;
}

WorkerGenerateKeyPair *newWorkerGenerateKeyPair(napi_env env, CK_C_GenerateKeyPair function, napi_value callback, CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR publicKeyAttributes, CK_ULONG publicKeyAttributesLength, CK_ATTRIBUTE_PTR privateKeyAttributes, CK_ULONG privateKeyAttributesLength)
{
  WorkerGenerateKeyPair *work = new WorkerGenerateKeyPair;
  work->function = function;
  work->rv = CKR_OK;
  work->sessionHandle = sessionHandle;
  work->mechanism = mechanism;
  work->publicKeyAttributes = publicKeyAttributes;
  work->publicKeyAttributesLength = publicKeyAttributesLength;
  work->privateKeyAttributes = privateKeyAttributes;
  work->privateKeyAttributesLength = privateKeyAttributesLength;
  napi_create_reference(env, callback, 1, &work->callback);

  napi_value resource_name;
  napi_create_string_utf8(env, "WorkerGenerateKeyPair", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_async_work(env, nullptr, resource_name, WorkerGenerateKeyPairExecute, WorkerGenerateKeyPairComplete, work, &work->work);
  napi_queue_async_work(env, work->work);

  return work;
}

struct WorkerDeriveKey
{
  napi_async_work work;
  napi_deferred deferred;
  napi_ref callback;
  CK_C_DeriveKey function;
  CK_RV rv;
  CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_OBJECT_HANDLE baseKeyHandle;
  CK_ATTRIBUTE_PTR attributes;
  CK_ULONG attributesLength;
  CK_OBJECT_HANDLE keyHandle;
};

void WorkerDeriveKeyExecute(napi_env env, void *data)
{
  WorkerDeriveKey *work = static_cast<WorkerDeriveKey *>(data);

  work->rv = work->function(
      work->sessionHandle,
      work->mechanism,
      work->baseKeyHandle,
      work->attributes, work->attributesLength,
      &work->keyHandle);
}

void WorkerDeriveKeyComplete(napi_env env, napi_status status, void *data)
{
  WorkerDeriveKey *work = static_cast<WorkerDeriveKey *>(data);
  MechanismWrapper mechanism(work->mechanism, true);
  AttributesWrapper attributes(work->attributes, work->attributesLength, true);

  napi_value callback;
  napi_get_reference_value(env, work->callback, &callback);
  napi_value global;
  napi_get_global(env, &global);
  napi_value argv[2];
  napi_value nullValue;
  napi_get_null(env, &nullValue);

  if (work->rv == CKR_OK)
  {
    napi_value keyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &work->keyHandle, nullptr, &keyHandle);

    argv[0] = nullValue;
    argv[1] = keyHandle;
  }
  else
  {
    const char *error_name = get_error_name(work->rv);
    char error_message[100];
    snprintf(error_message, sizeof(error_message), "%s:%lu", error_name, work->rv);
    napi_value errorMessage;
    napi_create_string_utf8(env, error_message, NAPI_AUTO_LENGTH, &errorMessage);
    napi_value error;
    napi_create_error(env, nullptr, errorMessage, &error);

    argv[0] = error;
    argv[1] = nullValue;
  }

  napi_call_function(env, global, callback, 2, argv, nullptr);
  napi_delete_reference(env, work->callback);

  napi_delete_async_work(env, work->work);
  delete work;
}

WorkerDeriveKey *newWorkerDeriveKey(
    napi_env env,
    CK_C_DeriveKey function,
    napi_value callback,
    CK_SESSION_HANDLE sessionHandle,
    CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE baseKeyHandle,
    CK_ATTRIBUTE_PTR attributes,
    CK_ULONG attributesLength)
{
  WorkerDeriveKey *work = new WorkerDeriveKey;
  work->function = function;
  work->rv = CKR_OK;
  work->sessionHandle = sessionHandle;
  work->mechanism = mechanism;
  work->baseKeyHandle = baseKeyHandle;
  work->attributes = attributes;
  work->attributesLength = attributesLength;
  napi_create_reference(env, callback, 1, &work->callback);

  napi_value resource_name;
  napi_create_string_utf8(env, "WorkerDeriveKey", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_async_work(env, nullptr, resource_name, WorkerDeriveKeyExecute, WorkerDeriveKeyComplete, work, &work->work);
  napi_queue_async_work(env, work->work);

  return work;
}

struct WorkerWrapKey
{
  napi_async_work work;
  napi_deferred deferred;
  napi_ref callback;
  CK_C_WrapKey function;
  CK_RV rv;
  CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_OBJECT_HANDLE wrappingKeyHandle;
  CK_OBJECT_HANDLE keyHandle;
  CK_BYTE_PTR wrappedKey;
  CK_ULONG wrappedKeyLength;
};

void WorkerWrapKeyExecute(napi_env env, void *data)
{
  WorkerWrapKey *work = static_cast<WorkerWrapKey *>(data);

  work->rv = work->function(
      work->sessionHandle,
      work->mechanism,
      work->wrappingKeyHandle,
      work->keyHandle,
      work->wrappedKey,
      &work->wrappedKeyLength);
}

void WorkerWrapKeyComplete(napi_env env, napi_status status, void *data)
{
  WorkerWrapKey *work = static_cast<WorkerWrapKey *>(data);
  MechanismWrapper mechanism(work->mechanism, true);

  napi_value callback;
  napi_get_reference_value(env, work->callback, &callback);
  napi_value global;
  napi_get_global(env, &global);
  napi_value argv[2];
  napi_value nullValue;
  napi_get_null(env, &nullValue);

  if (work->rv == CKR_OK)
  {
    napi_value wrappedKey;
    napi_create_buffer_copy(env, work->wrappedKeyLength, work->wrappedKey, nullptr, &wrappedKey);

    argv[0] = nullValue;
    argv[1] = wrappedKey;
  }
  else
  {
    const char *error_name = get_error_name(work->rv);
    char error_message[100];
    snprintf(error_message, sizeof(error_message), "%s:%lu", error_name, work->rv);
    napi_value errorMessage;
    napi_create_string_utf8(env, error_message, NAPI_AUTO_LENGTH, &errorMessage);
    napi_value error;
    napi_create_error(env, nullptr, errorMessage, &error);

    argv[0] = error;
    argv[1] = nullValue;
  }

  napi_call_function(env, global, callback, 2, argv, nullptr);
  napi_delete_reference(env, work->callback);

  napi_delete_async_work(env, work->work);
  delete work;
}

WorkerWrapKey *newWorkerWrapKey(
    napi_env env,
    CK_C_WrapKey function,
    napi_value callback,
    CK_SESSION_HANDLE sessionHandle,
    CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE wrappingKeyHandle,
    CK_OBJECT_HANDLE keyHandle,
    CK_BYTE_PTR wrappedKey,
    CK_ULONG wrappedKeyLength)
{
  WorkerWrapKey *work = new WorkerWrapKey;
  work->function = function;
  work->rv = CKR_OK;
  work->sessionHandle = sessionHandle;
  work->mechanism = mechanism;
  work->wrappingKeyHandle = wrappingKeyHandle;
  work->keyHandle = keyHandle;
  work->wrappedKey = wrappedKey;
  work->wrappedKeyLength = wrappedKeyLength;
  napi_create_reference(env, callback, 1, &work->callback);

  napi_value resource_name;
  napi_create_string_utf8(env, "WorkerWrapKey", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_async_work(env, nullptr, resource_name, WorkerWrapKeyExecute, WorkerWrapKeyComplete, work, &work->work);
  napi_queue_async_work(env, work->work);

  return work;
}

struct WorkerUnwrapKey
{
  napi_async_work work;
  napi_deferred deferred;
  napi_ref callback;
  CK_C_UnwrapKey function;
  CK_RV rv;
  CK_SESSION_HANDLE sessionHandle;
  CK_MECHANISM_PTR mechanism;
  CK_OBJECT_HANDLE unwrappingKeyHandle;
  CK_BYTE_PTR wrappedKey;
  CK_ULONG wrappedKeyLength;
  CK_ATTRIBUTE_PTR attributes;
  CK_ULONG attributesLength;
  CK_OBJECT_HANDLE keyHandle;
};

void WorkerUnwrapKeyExecute(napi_env env, void *data)
{
  WorkerUnwrapKey *work = static_cast<WorkerUnwrapKey *>(data);

  work->rv = work->function(
      work->sessionHandle,
      work->mechanism,
      work->unwrappingKeyHandle,
      work->wrappedKey,
      work->wrappedKeyLength,
      work->attributes, work->attributesLength,
      &work->keyHandle);
}

void WorkerUnwrapKeyComplete(napi_env env, napi_status status, void *data)
{
  WorkerUnwrapKey *work = static_cast<WorkerUnwrapKey *>(data);
  MechanismWrapper mechanism(work->mechanism, true);
  AttributesWrapper attributes(work->attributes, work->attributesLength, true);

  napi_value callback;
  napi_get_reference_value(env, work->callback, &callback);
  napi_value global;
  napi_get_global(env, &global);
  napi_value argv[2];
  napi_value nullValue;
  napi_get_null(env, &nullValue);

  if (work->rv == CKR_OK)
  {
    napi_value keyHandle;
    napi_create_buffer_copy(env, sizeof(CK_OBJECT_HANDLE), &work->keyHandle, nullptr, &keyHandle);

    argv[0] = nullValue;
    argv[1] = keyHandle;
  }
  else
  {
    const char *error_name = get_error_name(work->rv);
    char error_message[100];
    snprintf(error_message, sizeof(error_message), "%s:%lu", error_name, work->rv);
    napi_value errorMessage;
    napi_create_string_utf8(env, error_message, NAPI_AUTO_LENGTH, &errorMessage);
    napi_value error;
    napi_create_error(env, nullptr, errorMessage, &error);

    argv[0] = error;
    argv[1] = nullValue;
  }

  napi_call_function(env, global, callback, 2, argv, nullptr);
  napi_delete_reference(env, work->callback);

  napi_delete_async_work(env, work->work);
  delete work;
}

WorkerUnwrapKey *newWorkerUnwrapKey(
    napi_env env,
    CK_C_UnwrapKey function,
    napi_value callback,
    CK_SESSION_HANDLE sessionHandle,
    CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE unwrappingKeyHandle,
    CK_BYTE_PTR wrappedKey,
    CK_ULONG wrappedKeyLength,
    CK_ATTRIBUTE_PTR attributes,
    CK_ULONG attributesLength)
{
  WorkerUnwrapKey *work = new WorkerUnwrapKey;
  work->function = function;
  work->rv = CKR_OK;
  work->sessionHandle = sessionHandle;
  work->mechanism = mechanism;
  work->unwrappingKeyHandle = unwrappingKeyHandle;
  work->wrappedKey = wrappedKey;
  work->wrappedKeyLength = wrappedKeyLength;
  work->attributes = attributes;
  work->attributesLength = attributesLength;
  napi_create_reference(env, callback, 1, &work->callback);

  napi_value resource_name;
  napi_create_string_utf8(env, "WorkerUnwrapKey", NAPI_AUTO_LENGTH, &resource_name);
  napi_create_async_work(env, nullptr, resource_name, WorkerUnwrapKeyExecute, WorkerUnwrapKeyComplete, work, &work->work);
  napi_queue_async_work(env, work->work);

  return work;
}
