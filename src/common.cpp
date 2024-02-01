/**
 * @file common.cpp
 * @brief Implementation of common functions used in the project.
 */
#include "common.h"

const char *get_error_name(CK_RV rv)
{
#define CASE(x) \
  case x:       \
    return #x;
  switch (rv)
  {
    CASE(CKR_OK)
    CASE(CKR_CANCEL)
    CASE(CKR_HOST_MEMORY)
    CASE(CKR_SLOT_ID_INVALID)
    CASE(CKR_GENERAL_ERROR)
    CASE(CKR_FUNCTION_FAILED)
    CASE(CKR_ARGUMENTS_BAD)
    CASE(CKR_NO_EVENT)
    CASE(CKR_NEED_TO_CREATE_THREADS)
    CASE(CKR_CANT_LOCK)
    CASE(CKR_ATTRIBUTE_READ_ONLY)
    CASE(CKR_ATTRIBUTE_SENSITIVE)
    CASE(CKR_ATTRIBUTE_TYPE_INVALID)
    CASE(CKR_ATTRIBUTE_VALUE_INVALID)
    CASE(CKR_DATA_INVALID)
    CASE(CKR_DATA_LEN_RANGE)
    CASE(CKR_DEVICE_ERROR)
    CASE(CKR_DEVICE_MEMORY)
    CASE(CKR_DEVICE_REMOVED)
    CASE(CKR_ENCRYPTED_DATA_INVALID)
    CASE(CKR_ENCRYPTED_DATA_LEN_RANGE)
    CASE(CKR_FUNCTION_CANCELED)
    CASE(CKR_FUNCTION_NOT_PARALLEL)
    CASE(CKR_FUNCTION_NOT_SUPPORTED)
    CASE(CKR_KEY_HANDLE_INVALID)
    CASE(CKR_KEY_SIZE_RANGE)
    CASE(CKR_KEY_TYPE_INCONSISTENT)
    CASE(CKR_KEY_NOT_NEEDED)
    CASE(CKR_KEY_CHANGED)
    CASE(CKR_KEY_NEEDED)
    CASE(CKR_KEY_INDIGESTIBLE)
    CASE(CKR_KEY_FUNCTION_NOT_PERMITTED)
    CASE(CKR_KEY_NOT_WRAPPABLE)
    CASE(CKR_KEY_UNEXTRACTABLE)
    CASE(CKR_MECHANISM_INVALID)
    CASE(CKR_MECHANISM_PARAM_INVALID)
    CASE(CKR_OBJECT_HANDLE_INVALID)
    CASE(CKR_OPERATION_ACTIVE)
    CASE(CKR_OPERATION_NOT_INITIALIZED)
    CASE(CKR_PIN_INCORRECT)
    CASE(CKR_PIN_INVALID)
    CASE(CKR_PIN_LEN_RANGE)
    CASE(CKR_PIN_EXPIRED)
    CASE(CKR_PIN_LOCKED)
    CASE(CKR_SESSION_CLOSED)
    CASE(CKR_SESSION_COUNT)
    CASE(CKR_SESSION_HANDLE_INVALID)
    CASE(CKR_SESSION_PARALLEL_NOT_SUPPORTED)
    CASE(CKR_SESSION_READ_ONLY)
    CASE(CKR_SESSION_EXISTS)
    CASE(CKR_SESSION_READ_ONLY_EXISTS)
    CASE(CKR_SESSION_READ_WRITE_SO_EXISTS)
    CASE(CKR_SIGNATURE_INVALID)
    CASE(CKR_SIGNATURE_LEN_RANGE)
    CASE(CKR_TEMPLATE_INCOMPLETE)
    CASE(CKR_TEMPLATE_INCONSISTENT)
    CASE(CKR_TOKEN_NOT_PRESENT)
    CASE(CKR_TOKEN_NOT_RECOGNIZED)
    CASE(CKR_TOKEN_WRITE_PROTECTED)
    CASE(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    CASE(CKR_UNWRAPPING_KEY_SIZE_RANGE)
    CASE(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
    CASE(CKR_USER_ALREADY_LOGGED_IN)
    CASE(CKR_USER_NOT_LOGGED_IN)
    CASE(CKR_USER_PIN_NOT_INITIALIZED)
    CASE(CKR_USER_TYPE_INVALID)
    CASE(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
    CASE(CKR_USER_TOO_MANY_TYPES)
    CASE(CKR_WRAPPED_KEY_INVALID)
    CASE(CKR_WRAPPED_KEY_LEN_RANGE)
    CASE(CKR_WRAPPING_KEY_HANDLE_INVALID)
    CASE(CKR_WRAPPING_KEY_SIZE_RANGE)
    CASE(CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
    CASE(CKR_RANDOM_SEED_NOT_SUPPORTED)
    CASE(CKR_RANDOM_NO_RNG)
    CASE(CKR_DOMAIN_PARAMS_INVALID)
    CASE(CKR_BUFFER_TOO_SMALL)
    CASE(CKR_SAVED_STATE_INVALID)
    CASE(CKR_INFORMATION_SENSITIVE)
    CASE(CKR_STATE_UNSAVEABLE)
    CASE(CKR_CRYPTOKI_NOT_INITIALIZED)
    CASE(CKR_CRYPTOKI_ALREADY_INITIALIZED)
    CASE(CKR_MUTEX_BAD)
    CASE(CKR_MUTEX_NOT_LOCKED)
    CASE(CKR_NEW_PIN_MODE)
    CASE(CKR_NEXT_OTP)
    CASE(CKR_EXCEEDED_MAX_ITERATIONS)
    CASE(CKR_FIPS_SELF_TEST_FAILED)
    CASE(CKR_LIBRARY_LOAD_FAILED)
    CASE(CKR_PIN_TOO_WEAK)
    CASE(CKR_PUBLIC_KEY_INVALID)
    CASE(CKR_FUNCTION_REJECTED)
  default:
    return "CKR_VENDOR_DEFINED";
  }
#undef CASE
}

void throw_rv_error(napi_env env, CK_RV rv)
{
  const char *errorName = get_error_name(rv);
  char error_message[100];
  snprintf(error_message, sizeof(error_message), "%s:%lu", errorName, rv);
  napi_throw_error(env, nullptr, error_message);
}

void throw_type_errorf(napi_env env, const char *format, ...)
{
  char error_message[256];
  va_list args;
  va_start(args, format);
  vsnprintf(error_message, sizeof(error_message), format, args);
  va_end(args);
  napi_throw_type_error(env, nullptr, error_message);
}

bool is_object(napi_env env, napi_value value)
{
  napi_valuetype type;
  napi_typeof(env, value, &type);
  return type == napi_object;
}

bool is_string(napi_env env, napi_value value)
{
  napi_valuetype type;
  napi_typeof(env, value, &type);
  return type == napi_string;
}

bool is_number(napi_env env, napi_value value)
{
  napi_valuetype type;
  napi_typeof(env, value, &type);
  return type == napi_number;
}

bool is_array(napi_env env, napi_value value)
{
  bool is_array;
  napi_is_array(env, value, &is_array);
  return is_array;
}

bool is_buffer(napi_env env, napi_value value)
{
  bool is_buffer;
  napi_is_buffer(env, value, &is_buffer);
  return is_buffer;
}

bool is_empty(napi_env env, napi_value value)
{
  napi_valuetype type;
  napi_typeof(env, value, &type);
  return type == napi_undefined || type == napi_null;
}

bool is_function(napi_env env, napi_value value)
{
  napi_valuetype type;
  napi_typeof(env, value, &type);
  return type == napi_function;
}

MechanismWrapper::MechanismWrapper(CK_MECHANISM *mechanism, bool dispose)
{
  this->value = mechanism;
  this->dispose = dispose;
}

MechanismWrapper::MechanismWrapper()
{
  this->value = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
  this->dispose = true;
}

MechanismWrapper::~MechanismWrapper()
{
  if (this->dispose && this->value != nullptr)
  {
    if (this->value->pParameter != nullptr)
    {
      free(this->value->pParameter);
    }
    free(this->value);
  }
}

AttributesWrapper::AttributesWrapper(CK_ATTRIBUTE_PTR attributes, CK_ULONG length, bool dispose)
{
  this->attributes = attributes;
  this->length = length;
  this->dispose = dispose;
}

AttributesWrapper::AttributesWrapper(CK_ULONG length)
{
  this->length = length;
  this->attributes = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * length);
  this->dispose = true;
}

AttributesWrapper::~AttributesWrapper()
{
  if (dispose && attributes != nullptr)
  {
    for (int i = 0; i < int(length); i++)
    {
      if (attributes[i].pValue != nullptr)
      {
        free(attributes[i].pValue);
        attributes[i].pValue = nullptr;
      }
    }
    free(attributes);
    attributes = nullptr;
    length = 0;
  }
}

void AttributesWrapper::allocValue(CK_ULONG index, CK_ULONG length)
{
  CK_ATTRIBUTE_PTR attr = &attributes[index];
  if (length == 0)
  {
    attr->pValue = nullptr;
    attr->ulValueLen = 0;
    return;
  }
  attr->pValue = malloc(sizeof(CK_BYTE) * length);
  attr->ulValueLen = length;
  this->dispose = true;
}

void AttributesWrapper::allocAllValues()
{
  for (int i = 0; i < int(length); i++)
  {
    allocValue(i, attributes[i].ulValueLen);
  }
}
