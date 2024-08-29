/**
 * @file pkcs11.cpp
 * @brief Implementation of PKCS11 functions.
 *
 * This file contains the implementation of various PKCS11 functions.
 */
#include "common.h"

#include "params.cpp"
#include "worker.cpp"

napi_ref constructorRef;

/**
 * @brief Creates a PKCS11 version object from a CK_VERSION structure.
 *
 * @param env The N-API environment.
 * @param version The CK_VERSION structure representing the version.
 * @return The PKCS11 version object.
 */
napi_value create_version(napi_env env, CK_VERSION version)
{
  // { major: number, minor: number }
  napi_value jsVersion;
  napi_create_object(env, &jsVersion);

  // major
  napi_value major;
  napi_create_uint32(env, version.major, &major);
  napi_set_named_property(env, jsVersion, "major", major);

  // minor
  napi_value minor;
  napi_create_uint32(env, version.minor, &minor);
  napi_set_named_property(env, jsVersion, "minor", minor);

  return jsVersion;
}

/**
 * @brief Creates a PKCS11 date object from a utcTime string of the format YYYYMMDDhhmmssZ.
 *
 * @param env The N-API environment.
 * @param utcTime A pointer to the UTC time string.
 */
napi_value create_date_utc_property(napi_env env, CK_UTF8CHAR_PTR utcTime)
{
  char timeStr[17];
  strncpy(timeStr, (char *)utcTime, 16);
  timeStr[16] = '\0'; // Null-terminate the string

  napi_value jsUtcTime;
  napi_create_string_utf8(env, timeStr, NAPI_AUTO_LENGTH, &jsUtcTime);

  return jsUtcTime;
}

/**
 * @brief A macro that checks if a given index is within the range of the argument list size.
 *
 * If the index is out of range, it throws a type error indicating that the argument at the specified
 * index is required.
 *
 * @param index The index to check.
 */
#define ASSERT_ARGS_INDEX(index)                                 \
  if (argc <= index)                                             \
  {                                                              \
    THROW_TYPE_ERRORF(false, "Argument %lu is required", index); \
  }

/**
 * @brief Retrieves an unsigned long argument from a given index in the argument list.
 *
 * @param env The N-API environment.
 * @param arg The argument list.
 * @param argc The number of arguments in the list.
 * @param index The index of the argument to retrieve.
 * @param value Pointer to store the retrieved unsigned long value.
 * @return Returns true if the argument was successfully retrieved, false otherwise.
 */
bool get_args_ulong(napi_env env, napi_value *arg, size_t argc, size_t index, CK_ULONG *value)
{
  ASSERT_ARGS_INDEX(index);

  // check type
  if (!is_number(env, arg[index]))
  {
    THROW_TYPE_ERRORF(false, "Argument %lu has wrong type. Should be a Number", index);
  }

  // get value
  uint32_t temp = 0;
  napi_get_value_uint32(env, arg[index], &temp);

  // set value
  *value = temp;

  return true;
}

/**
 * @brief A macro that retrieves an unsigned long integer from the argument list at a specified index.
 *
 * @param index The index of the argument to retrieve.
 * @param value The variable to store the retrieved value.
 */
#define GET_ARGS_ULONG(index, value)                      \
  CK_ULONG value;                                         \
  if (!get_args_ulong(env, &arg[0], argc, index, &value)) \
  {                                                       \
    return nullptr;                                       \
  }

/**
 * @brief Retrieves the buffer from the specified argument at the given index.
 *
 * @param env The N-API environment.
 * @param arg The array of N-API values representing the arguments.
 * @param argc The number of arguments in the array.
 * @param index The index of the argument to retrieve.
 * @param data A pointer to store the address of the buffer.
 * @param length A pointer to store the length of the buffer.
 * @return true if the buffer was successfully retrieved, false otherwise.
 */
bool get_args_buffer(napi_env env, napi_value *arg, size_t argc, size_t index, void **data, size_t *length)
{
  ASSERT_ARGS_INDEX(index);

  // check type
  bool isBuffer;
  napi_is_buffer(env, arg[index], &isBuffer);
  if (!isBuffer)
  {
    THROW_TYPE_ERRORF(false, "Argument %lu has wrong type. Should be a Buffer", index);
  }

  // get buffer info
  napi_get_buffer_info(env, arg[index], data, length);

  return true;
}

/**
 * @brief A macro that retrieves a buffer from the argument list at a specified index.
 *
 * It creates two variables, one for the buffer address (<data>) and one for the buffer
 * length (<data>Length).
 *
 * @param index The index of the argument to retrieve.
 * @param data The variable to store the retrieved buffer address.
 */
#define GET_ARGS_BUFFER(index, data)                                     \
  void *data;                                                            \
  size_t data##Length;                                                   \
  if (!get_args_buffer(env, &arg[0], argc, index, &data, &data##Length)) \
  {                                                                      \
    return nullptr;                                                      \
  }

/**
 * @brief Get the handle object from the argument list at a specified index.
 *
 * @param env The N-API environment.
 * @param arg The array of N-API values representing the arguments.
 * @param argc The number of arguments in the array.
 * @param index The index of the argument to retrieve.
 * @param handle A pointer to store the retrieved handle.
 * @return true if the handle was successfully retrieved, false otherwise.
 */
bool get_args_handle(napi_env env, napi_value *arg, size_t argc, size_t index, CK_ULONG *handle)
{
  // check type
  void *data;
  size_t length;
  if (!get_args_buffer(env, arg, argc, index, &data, &length))
  {
    return false;
  }

  // check length
  if (length != sizeof(CK_ULONG))
  {
    THROW_TYPE_ERRORF(false, "Argument %lu has wrong length. Should be %lu bytes.", index, sizeof(CK_ULONG));
  }

  // set value
  *handle = *(CK_OBJECT_HANDLE *)data;

  return true;
}

/**
 * @brief A macro that retrieves a handle from the argument list at a specified index.
 *
 * @param index The index of the argument to retrieve.
 * @param handle The variable to store the retrieved handle.
 */
#define GET_ARGS_HANDLE(index, handle)                      \
  CK_ULONG handle;                                          \
  if (!get_args_handle(env, &arg[0], argc, index, &handle)) \
  {                                                         \
    return nullptr;                                         \
  }

/**
 * @brief Get the slot ID object from the argument list at a specified index.
 *
 * @param env The N-API environment.
 * @param arg The array of N-API values representing the arguments.
 * @param argc The number of arguments in the array.
 * @param index The index of the argument to retrieve.
 * @param slotId A pointer to store the retrieved slot ID.
 * @return true if the slot ID was successfully retrieved, false otherwise.
 */
bool get_args_slot_id(napi_env env, napi_value *arg, size_t argc, size_t index, CK_SLOT_ID *slotId)
{
  // check type
  CK_ULONG handle;
  if (!get_args_handle(env, arg, argc, index, &handle))
  {
    return false;
  }

  // set value
  *slotId = (CK_SLOT_ID)handle;

  return true;
}

/**
 * @brief A macro that retrieves a slot ID from the argument list at a specified index.
 *
 * @param index The index of the argument to retrieve.
 * @param slotId The variable to store the retrieved slot ID.
 */
#define GET_ARGS_SLOT_ID(index, slotId)                      \
  CK_SLOT_ID slotId;                                         \
  if (!get_args_slot_id(env, &arg[0], argc, index, &slotId)) \
  {                                                          \
    return nullptr;                                          \
  }

/**
 * @brief Get the session handle object from the argument list at a specified index.
 *
 * @param env The N-API environment.
 * @param arg The array of N-API values representing the arguments.
 * @param argc The number of arguments in the array.
 * @param index The index of the argument to retrieve.
 * @param mechanismType A pointer to store the retrieved session handle.
 * @return true if the session handle was successfully retrieved, false otherwise.
 */
bool get_args_mechanism_type(napi_env env, napi_value *arg, size_t argc, size_t index, CK_MECHANISM_TYPE *mechanismType)
{
  // check type
  CK_ULONG handle;
  if (!get_args_ulong(env, arg, argc, index, &handle))
  {
    return false;
  }

  *mechanismType = (CK_MECHANISM_TYPE)handle;

  return true;
}

/**
 * @brief A macro that retrieves a mechanism type from the argument list at a specified index.
 *
 * @param index The index of the argument to retrieve.
 * @param mechanismType The variable to store the retrieved mechanism type.
 */
#define GET_ARGS_MECHANISM_TYPE(index, mechanismType)                      \
  CK_MECHANISM_TYPE mechanismType;                                         \
  if (!get_args_mechanism_type(env, &arg[0], argc, index, &mechanismType)) \
  {                                                                        \
    return nullptr;                                                        \
  }

/**
 * @brief Get the mechanism object from the argument list at a specified index.
 *
 * @param env The N-API environment.
 * @param arg The array of N-API values representing the arguments.
 * @param argc The number of arguments in the array.
 * @param index The index of the argument to retrieve.
 * @param sessionHandle A pointer to store the retrieved mechanism.
 * @return true if the mechanism was successfully retrieved, false otherwise.
 */
bool get_args_session_handle(napi_env env, napi_value *arg, size_t argc, size_t index, CK_SESSION_HANDLE *sessionHandle)
{
  // get handle
  CK_ULONG handle;
  if (!get_args_handle(env, arg, argc, index, &handle))
  {
    return false;
  }

  // set value
  *sessionHandle = (CK_SESSION_HANDLE)handle;

  return true;
}

/**
 * @brief A macro that retrieves a session handle from the argument list at a specified index.
 *
 * @param index The index of the argument to retrieve.
 * @param sessionHandle The variable to store the retrieved session handle.
 */
#define GET_ARGS_SESSION_HANDLE(index, sessionHandle)                      \
  CK_SESSION_HANDLE sessionHandle;                                         \
  if (!get_args_session_handle(env, &arg[0], argc, index, &sessionHandle)) \
  {                                                                        \
    return nullptr;                                                        \
  }

/**
 * @brief Get the mechanism object from the argument list at a specified index.
 *
 * @param env The N-API environment.
 * @param arg The array of N-API values representing the arguments.
 * @param argc The number of arguments in the array.
 * @param index The index of the argument to retrieve.
 * @param string A pointer to store the retrieved mechanism.
 * @param stringSize The size of the string buffer.
 * @param length A pointer to store the length of the string.
 * @return true if the mechanism was successfully retrieved, false otherwise.
 */
bool get_args_string(napi_env env, napi_value *arg, size_t argc, size_t index, char *string, size_t stringSize, size_t *length)
{
  ASSERT_ARGS_INDEX(index);

  napi_valuetype type;
  napi_typeof(env, arg[index], &type);
  if (type != napi_string)
  {
    THROW_TYPE_ERRORF(false, "Argument %lu has wrong type. Should be a String", index);
  }

  // get value
  napi_get_value_string_utf8(env, arg[index], nullptr, 0, length);
  if (*length != 0 && string != nullptr)
  {
    napi_get_value_string_utf8(env, arg[index], string, stringSize, length);
  }

  return true;
}

/**
 * @brief A macro that retrieves a string from the argument list at a specified index.
 *
 * @param index The index of the argument to retrieve.
 * @param string The variable to store the retrieved string.
 */
#define GET_ARGS_STRING(index, string)                                                          \
  size_t string##Length;                                                                        \
  if (!get_args_string(env, &arg[0], argc, index, nullptr, 0, &string##Length))                 \
  {                                                                                             \
    return nullptr;                                                                             \
  }                                                                                             \
  std::vector<char> string##Vector(string##Length + 1);                                         \
  char *string = string##Vector.data();                                                         \
  if (!get_args_string(env, &arg[0], argc, index, string, string##Length + 1, &string##Length)) \
  {                                                                                             \
    return nullptr;                                                                             \
  }

bool get_args_mechanism(napi_env env, napi_value *arg, size_t argc, size_t index, CK_MECHANISM *mechanism)
{
  ASSERT_ARGS_INDEX(index);

  // check type
  napi_valuetype type;
  napi_typeof(env, arg[index], &type);
  if (type != napi_object)
  {
    THROW_TYPE_ERRORF(false, "Argument %lu has wrong type. Should be an Object", index);
  }

  // get mechanism type
  napi_value mechanismTypeValue;
  napi_get_named_property(env, arg[index], "mechanism", &mechanismTypeValue);
  napi_valuetype mechanismTypeValueType;
  napi_typeof(env, mechanismTypeValue, &mechanismTypeValueType);
  if (mechanismTypeValueType != napi_number)
  {
    THROW_TYPE_ERRORF(false, "Argument %lu has wrong type. Property 'mechanism' should be a Number", index);
  }

  // get mechanism parameter
  napi_value mechanismParameter;
  napi_get_named_property(env, arg[index], "parameter", &mechanismParameter);
  napi_valuetype mechanismParameterType;
  napi_typeof(env, mechanismParameter, &mechanismParameterType);
  bool mechanismParameterIsBuffer = false;
  napi_is_buffer(env, mechanismParameter, &mechanismParameterIsBuffer);
  if (mechanismParameterType != napi_undefined && // undefined
      mechanismParameterType != napi_null &&      // null
      mechanismParameterType != napi_object &&    // Object
      mechanismParameterType != napi_number &&    // Number
      !mechanismParameterIsBuffer)                // Buffer
  {
    THROW_TYPE_ERRORF(false, "Argument %lu has wrong type. Property 'parameter' should be an Object or Buffer", index);
  }

  // set mechanism
  CK_MECHANISM_TYPE mechanismType;
  uint32_t temp = 0;
  napi_get_value_uint32(env, mechanismTypeValue, &temp);
  mechanismType = (CK_MECHANISM_TYPE)temp;
  mechanism->mechanism = mechanismType;

  // set mechanism parameter
  if (mechanismParameterIsBuffer)
  {
    // Buffer
    void *data;
    size_t length;
    napi_get_buffer_info(env, mechanismParameter, &data, &length);
    mechanism->pParameter = malloc(sizeof(CK_BYTE) * length);
    memcpy(mechanism->pParameter, data, length);
    mechanism->ulParameterLen = length;
  }
  else if (mechanismParameterType == napi_number)
  {
    // Number
    uint32_t value = 0;
    napi_get_value_uint32(env, mechanismParameter, &value);
    mechanism->pParameter = malloc(sizeof(CK_ULONG));
    *(CK_ULONG *)mechanism->pParameter = value;
    mechanism->ulParameterLen = sizeof(CK_ULONG);
  }
  else if (mechanismParameterType == napi_object)
  {
    // Object
    napi_value typeValue;
    napi_get_named_property(env, mechanismParameter, "type", &typeValue);
    if (!is_number(env, typeValue))
    {
      THROW_TYPE_ERRORF(false, "Argument %lu has wrong type. Property 'type' should be a Number", index);
    }

    uint32_t type = 0;
    napi_get_value_uint32(env, typeValue, &type);
    switch (type)
    {
    case CK_PARAMS_AES_CBC:
    {
      return get_params_aes_cbc(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_AES_CCM:
    {
      return get_params_aes_ccm(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_AES_GCM:
    {
      return get_params_aes_gcm(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_AES_GCM_v240:
    {
      return get_params_aes_gcm_240(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_RSA_PSS:
    {
      return get_params_rsa_pss(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_RSA_OAEP:
    {
      return get_params_rsa_oaep(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_EC_DH:
    {
      return get_params_ec_dh(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_ECDH2_DERIVE:
    {
      return get_params_ecdh2_derive(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_ECMQV_DERIVE:
    {
      return get_params_ecmqv_derive(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_X9_42_DH1_DERIVE:
    {
      return get_params_x9_42_dh1_derive(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_X9_42_DH2_DERIVE:
    {
      return get_params_x9_42_dh2_derive(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_X9_42_MQV_DERIVE:
    {
      return get_params_x9_42_mqv_derive(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_KEA_DERIVE:
    {
      return get_params_kea_derive(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_RC2_CBC:
    {
      return get_params_rc2_cbc(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_RC2_MAC_GENERAL:
    {
      return get_params_rc2_mac_general(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_RC5:
    {
      return get_params_rc5(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_RC5_CBC:
    {
      return get_params_rc5_cbc(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_RC5_MAC_GENERAL:
    {
      return get_params_rc5_mac_general(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_DES_CBC_ENCRYPT_DATA:
    {
      return get_params_des_cbc_encrypt_data(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_SKIPJACK_PRIVATE_WRAP:
    {
      return get_params_skipjack_private_wrap(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_SKIPJACK_RELAYX:
    {
      return get_params_skipjack_relayx(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_PBE:
    {
      return get_params_pbe(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_KEY_WRAP_SET_OAEP:
    {
      return get_params_key_wrap_set_oaep(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_GCM:
    {
      return get_params_gcm(env, mechanismParameter, mechanism);
    }
    case CK_PARAMS_CCM:
    {
      return get_params_ccm(env, mechanismParameter, mechanism);
    }
    case CK_PARAM_GOSTR3410_DERIVE:
    {
      return get_params_gost_r3410_derive(env, mechanismParameter, mechanism);
    }
    case CK_PARAM_GOSTR3410_KEY_WRAP:
    {
      return get_params_gost_r3410_key_wrap(env, mechanismParameter, mechanism);
    }
    }
  }
  else
  {
    mechanism->pParameter = nullptr;
    mechanism->ulParameterLen = 0;
  }

  return true;
}

/**
 * @brief A macro that retrieves a mechanism from the argument list at a specified index.
 *
 * @param index The index of the argument to retrieve.
 * @param mechanism The variable to store the retrieved mechanism.
 */
#define GET_ARGS_MECHANISM(index, mechanism)                           \
  MechanismWrapper mechanism;                                          \
  if (!get_args_mechanism(env, &arg[0], argc, index, mechanism.value)) \
  {                                                                    \
    return nullptr;                                                    \
  }

/**
 * @brief Get the attributes object from the argument list at a specified index.
 *
 * @param env The N-API environment.
 * @param attr The CK_ATTRIBUTE to store the retrieved attributes.
 * @param data The data to store the retrieved attributes.
 * @param length The length of the data.
 */
bool processDate(napi_env env, CK_ATTRIBUTE *attr, const char *data, size_t length)
{
  if (length < 8)
  {
    THROW_TYPE_ERRORF(false, "Attribute with type 0x%08lX is not convertible to CK_DATE. The length of the data should be at least 8 bytes.", attr->type);
  }

  CK_DATE *datePtr = (CK_DATE *)attr->pValue;
  char year[5], month[3], day[3];
  strncpy(year, data, 4);
  strncpy(month, data + 4, 2);
  strncpy(day, data + 6, 2);
  year[4] = month[2] = day[2] = '\0';
  strncpy((char *)datePtr->year, year, 4);
  strncpy((char *)datePtr->month, month, 2);
  strncpy((char *)datePtr->day, day, 2);

  return true;
}

/**
 * @brief Get the attributes object from the argument list at a specified index.
 *
 * @param env The N-API environment.
 * @param arg The array of N-API values representing the arguments.
 * @param argc The number of arguments in the array.
 * @param index The index of the argument to retrieve.
 * @param attrs A pointer to store the retrieved attributes. If nullptr, only the length is retrieved.
 * @param length A pointer to store the length of the attributes.
 * @return true if the attributes were successfully retrieved, false otherwise.
 */
bool get_args_attributes(napi_env env, napi_value *arg, size_t argc, size_t index, AttributesWrapper *attrs, CK_ULONG *length)
{
  ASSERT_ARGS_INDEX(index);

  // check type
  // { type: number, value?: number | boolean | string | Buffer  }[]
  bool isArray;
  napi_is_array(env, arg[index], &isArray);
  if (!isArray)
  {
    THROW_TYPE_ERRORF(false, "Argument %lu has wrong type. Should be an Array", index);
  }

  // get length
  napi_value array = arg[index];
  uint32_t arrayLength = 0;
  napi_get_array_length(env, array, &arrayLength);
  if (attrs != nullptr && arrayLength != attrs->length)
  {
    THROW_TYPE_ERRORF(false, "Parameter 'attrs' has wrong length. Should be %lu.", attrs->length);
  }
  *length = arrayLength;

  if (attrs == nullptr)
  {
    // only length is required
    return true;
  }

  // get attributes
  for (int i = 0; i < int(arrayLength); i++)
  {
    napi_value element;
    napi_get_element(env, array, i, &element);

    // check element type
    if (!is_object(env, element))
    {
      THROW_TYPE_ERRORF(false, "Element %d has wrong type. Should be an Object", i);
    }

    // type
    napi_value typeValue;
    napi_get_named_property(env, element, "type", &typeValue);
    if (!is_number(env, typeValue))
    {
      THROW_TYPE_ERRORF(false, "Element %d has wrong type. Property 'type' should be a Number", i);
    }

    // value
    napi_value valueValue;
    napi_get_named_property(env, element, "value", &valueValue);
    napi_valuetype valueValueType;
    napi_typeof(env, valueValue, &valueValueType);
    bool valueIsBuffer = false;
    napi_is_buffer(env, valueValue, &valueIsBuffer);
    if (valueValueType != napi_undefined && // undefined
        valueValueType != napi_null &&      // null
        valueValueType != napi_number &&    // Number
        valueValueType != napi_boolean &&   // Boolean
        valueValueType != napi_string &&    // String
        !valueIsBuffer)                     // Buffer
    {
      THROW_TYPE_ERRORF(false, "Element %d has wrong type. Property 'value' should be a Number, Boolean, String or Buffer", i);
    }

    CK_ATTRIBUTE_PTR attr = &attrs->attributes[i];

    uint32_t type = 0;
    napi_get_value_uint32(env, typeValue, &type);
    attr->type = (CK_ATTRIBUTE_TYPE)type;

    if (attr->type == CKA_START_DATE || attr->type == CKA_END_DATE)
    {
      if (valueValueType == napi_string)
      {
        size_t length;
        napi_get_value_string_utf8(env, valueValue, nullptr, 0, &length);
        attrs->allocValue(i, sizeof(CK_DATE));
        if (processDate(env, attr, (char *)valueValue, length) == false)
        {
          return false;
        }
      }
      else if (valueIsBuffer)
      {
        void *data;
        size_t length;
        napi_get_buffer_info(env, valueValue, &data, &length);
        attrs->allocValue(i, sizeof(CK_DATE));
        if (processDate(env, attr, (char *)data, length) == false)
        {
          return false;
        }
      }
      else if (valueValueType == napi_undefined || valueValueType == napi_null)
      {
        // do nothing
      }
      else
      {
        THROW_TYPE_ERRORF(false, "Attribute with type 0x%08lX is not convertible to CK_DATE. Should be a String, Buffer or Date", attr->type);
      }
    }

    if (valueValueType == napi_undefined || valueValueType == napi_null)
    {
      attrs->allocValue(i, 0);
    }
    else if (valueValueType == napi_number)
    {
      attrs->allocValue(i, sizeof(CK_ULONG));
      uint32_t value = 0;
      napi_get_value_uint32(env, valueValue, &value);
      *(CK_ULONG *)attr->pValue = value;
    }
    else if (valueValueType == napi_boolean)
    {
      attrs->allocValue(i, sizeof(CK_BBOOL));
      bool value;
      napi_get_value_bool(env, valueValue, &value);
      *(CK_BBOOL *)attr->pValue = value ? CK_TRUE : CK_FALSE;
    }
    else if (valueValueType == napi_string)
    {
      size_t length;
      napi_get_value_string_utf8(env, valueValue, nullptr, 0, &length);
      attrs->allocValue(i, length + 1);
      attrs->attributes[i].ulValueLen = length; // length without null terminator
      napi_get_value_string_utf8(env, valueValue, (char *)attr->pValue, length + 1, &length);
    }
    else if (valueIsBuffer)
    {
      void *data;
      size_t length;
      napi_get_buffer_info(env, valueValue, &data, &length);
      attrs->allocValue(i, length);
      memcpy(attr->pValue, data, length);
    }
  }

  return true;
}

/**
 * @brief A macro that retrieves attributes from the argument list at a specified index.
 *
 * It creates two variables, one for the attributes (<attrs>) and one for the attributes
 * length (<attrs>Length).
 *
 * @param index The index of the argument to retrieve.
 * @param attrs The variable to store the retrieved attributes.
 */
#define GET_ARGS_ATTRIBUTES(index, attrs)                                       \
  CK_ULONG attrs##Length;                                                       \
  if (!get_args_attributes(env, &arg[0], argc, index, nullptr, &attrs##Length)) \
  {                                                                             \
    return nullptr;                                                             \
  }                                                                             \
  AttributesWrapper attrs(attrs##Length);                                       \
  if (!get_args_attributes(env, &arg[0], argc, index, &attrs, &attrs##Length))  \
  {                                                                             \
    return nullptr;                                                             \
  }

#define GET_ARGS_CALLBACK(index, callback)                                                  \
  napi_value callback = arg[index];                                                         \
  if (!is_function(env, callback))                                                          \
  {                                                                                         \
    THROW_TYPE_ERRORF(nullptr, "Argument %lu has wrong type. Should be a Function", index); \
  }

/**
 * @brief Get a list of arguments from the function call.
 *
 * @param env The N-API environment.
 * @param info The N-API callback info.
 * @param argc The number of arguments to retrieve.
 * @param arg A pointer to store the retrieved arguments.
 * @return true if the arguments were successfully retrieved, false otherwise.
 */
bool get_args(napi_env env, napi_callback_info info, size_t argc, napi_value *arg)
{
  napi_value jsthis;
  size_t length = 0;
  napi_get_cb_info(env, info, &length, nullptr, &jsthis, nullptr);
  if (length != argc)
  {
    THROW_TYPE_ERRORF(false, "Parameters are required. Expected %lu arguments, but received %lu.", argc, length);
  }

  napi_get_cb_info(env, info, &length, arg, &jsthis, nullptr);

  return true;
}

/**
 * @brief A macro that retrieves a list of arguments from the function call.
 *
 * @param expectedArgc The number of arguments to retrieve.
 * @param args The variable to store the retrieved arguments.
 */
#define GET_ARGS(expectedArgc, args)           \
  size_t argc = expectedArgc;                  \
  std::vector<napi_value> args(argc);          \
  if (!get_args(env, info, argc, args.data())) \
  {                                            \
    return nullptr;                            \
  }

/**
 * @brief A macro that checks if the CK_RV is CKR_OK and throws an error if not.
 *
 * @param rv The CK_RV to check.
 */
#define ASSERT_RV(rv)        \
  if (rv != CKR_OK)          \
  {                          \
    throw_rv_error(env, rv); \
    return nullptr;          \
  }

/**
 * @brief A macro that unwraps the PKCS11 object from the function call.
 */
#define UNWRAP_PKCS11()                                             \
  napi_value jsthis;                                                \
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);  \
  Pkcs11 *pkcs11;                                                   \
  napi_unwrap(env, jsthis, (void **)&pkcs11);                       \
  if (pkcs11->handle == nullptr)                                    \
  {                                                                 \
    napi_throw_error(env, nullptr, "PKCS11 module not loaded yet"); \
    return nullptr;                                                 \
  }

class Pkcs11
{
public:
  void *handle;
  CK_FUNCTION_LIST_PTR functionList;

  Pkcs11() : handle(nullptr), functionList(nullptr) {}

  ~Pkcs11()
  {
    if (handle != nullptr)
    {
      dlclose(handle);
      handle = nullptr;
    }
  }

  static napi_value Constructor(napi_env env, napi_callback_info info)
  {
    napi_value target;
    napi_get_new_target(env, info, &target);

    bool isConstructor = target != nullptr;

    if (isConstructor)
    {
      napi_value jsthis;
      napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

      Pkcs11 *pkcs11 = new Pkcs11();
      napi_wrap(env, jsthis, pkcs11, Pkcs11::Destructor, nullptr, nullptr);

      return jsthis;
    }
    else
    {
      napi_value cons;
      napi_get_reference_value(env, constructorRef, &cons);

      napi_value instance;
      napi_new_instance(env, cons, 0, nullptr, &instance);

      return instance;
    }
  }

  static void Destructor(napi_env env, void *nativeObject, void *finalize_hint)
  {
    Pkcs11 *pkcs11 = static_cast<Pkcs11 *>(nativeObject);
    pkcs11->~Pkcs11();
  }

  /**
   * @brief Loads the PKCS11 module.
   *
   * @param env The N-API environment.
   * @param info The N-API callback info.
   * @return The loaded PKCS11 module.
   */
  static napi_value Load(napi_env env, napi_callback_info info)
  {
    napi_value jsthis;
    napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

    Pkcs11 *pkcs11;
    napi_unwrap(env, jsthis, (void **)&pkcs11);

    size_t argc = 1;
    napi_value arg[1];
    napi_get_cb_info(env, info, &argc, arg, nullptr, nullptr);

    size_t length;
    napi_get_value_string_utf8(env, arg[0], nullptr, 0, &length);

    std::vector<char> path(length + 1);
    char *pPath = path.data();
    napi_get_value_string_utf8(env, arg[0], pPath, length + 1, &length);

    pkcs11->handle = dlopen(pPath, RTLD_LAZY | RTLD_LOCAL);
    if (pkcs11->handle == nullptr)
    {
      napi_throw_error(env, nullptr, dlerror());
      return nullptr;
    }

    CK_C_GetFunctionList pC_GetFunctionList = (CK_C_GetFunctionList)dlsym(pkcs11->handle, "C_GetFunctionList");
    if (pC_GetFunctionList == nullptr)
    {
      napi_throw_error(env, nullptr, dlerror());
      return nullptr;
    }

    CK_RV rv = pC_GetFunctionList(&pkcs11->functionList);
    ASSERT_RV(rv);

    return nullptr;
  }

  /**
   * @brief Closes the PKCS11 module.
   *
   * @param env The N-API environment.
   * @param info The N-API callback info.
   * @return Nothing.
   */
  static napi_value Close(napi_env env, napi_callback_info info)
  {
    napi_value jsthis;
    napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

    Pkcs11 *pkcs11;
    napi_unwrap(env, jsthis, (void **)&pkcs11);

    if (pkcs11->handle != nullptr)
    {
      dlclose(pkcs11->handle);
      pkcs11->handle = nullptr;
    }

    return nullptr;
  }

  static napi_value C_Initialize(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    // Read arguments
    size_t argc = 1;
    napi_value arg[1];
    napi_get_cb_info(env, info, &argc, arg, nullptr, nullptr);

    CK_VOID_PTR pInitArgs = nullptr;
    CK_NSS_C_INITIALIZE_ARGS nssInitArgs = {nullptr, nullptr, nullptr, nullptr, 0, nullptr, nullptr};
    CK_C_INITIALIZE_ARGS initArgs = {nullptr, nullptr, nullptr, nullptr, 0, nullptr};
    CK_CHAR_PTR path = NULL;
    if (argc > 0 && !is_empty(env, arg[0]))
    {
      napi_valuetype type;
      napi_typeof(env, arg[0], &type);

      if (type != napi_object)
      {
        THROW_TYPE_ERRORF(nullptr, "Argument %lu has wrong type. Should be an Object", 0);
      }

      // Read common C_Initialize args
      napi_value flags;
      napi_get_named_property(env, arg[0], "flags", &flags);
      uint32_t ckFlags = 0;
      napi_get_value_uint32(env, flags, &ckFlags);

      bool hasLibraryParameters;
      napi_has_named_property(env, arg[0], "libraryParameters", &hasLibraryParameters);
      if (hasLibraryParameters)
      {
        // Read NSS C_Initialize args
        napi_value libraryParameters;
        napi_get_named_property(env, arg[0], "libraryParameters", &libraryParameters);
        napi_valuetype type;
        napi_typeof(env, libraryParameters, &type);

        if (type != napi_string)
        {
          THROW_TYPE_ERRORF(nullptr, "Argument %lu has wrong type. Property 'libraryParameters' should be a String", 0);
        }

        size_t length;
        napi_get_value_string_utf8(env, libraryParameters, nullptr, 0, &length);

        path = new CK_CHAR[length];
        napi_get_value_string_utf8(env, libraryParameters, (char *)path, length, &length);

        nssInitArgs.flags = (CK_FLAGS)ckFlags;
        nssInitArgs.LibraryParameters = (CK_CHAR_PTR)path;

        pInitArgs = &nssInitArgs;
      }
      else
      {
        // Read common C_Initialize args
        initArgs.flags = (CK_FLAGS)ckFlags;

        pInitArgs = &initArgs;
      }
    }

    if (pInitArgs == nullptr)
    {
      pInitArgs = &initArgs;
    }

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Initialize(pInitArgs);
    if (path != nullptr)
    {
      delete[] path;
    }
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_Finalize(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Finalize(nullptr);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_GetInfo(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    // Call PKCS11 function
    CK_INFO ckInfo = {};
    CK_RV rv = pkcs11->functionList->C_GetInfo(&ckInfo);
    ASSERT_RV(rv);

    // Create result object
    napi_value result;
    napi_create_object(env, &result);

    napi_value cryptokiVersion = create_version(env, ckInfo.cryptokiVersion);
    napi_set_named_property(env, result, "cryptokiVersion", cryptokiVersion);

    napi_value manufacturerID;
    napi_create_string_utf8(env, (char *)&ckInfo.manufacturerID[0], sizeof(ckInfo.manufacturerID), &manufacturerID);
    napi_set_named_property(env, result, "manufacturerID", manufacturerID);

    napi_value flags;
    napi_create_uint32(env, ckInfo.flags, &flags);
    napi_set_named_property(env, result, "flags", flags);

    napi_value libraryDescription;
    napi_create_string_utf8(env, (char *)&ckInfo.libraryDescription[0], sizeof(ckInfo.libraryDescription), &libraryDescription);
    napi_set_named_property(env, result, "libraryDescription", libraryDescription);

    napi_value libraryVersion = create_version(env, ckInfo.libraryVersion);
    napi_set_named_property(env, result, "libraryVersion", libraryVersion);

    return result;
  }

  static napi_value C_GetSlotList(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    // Read arguments
    CK_BBOOL ckTokenPresent = CK_FALSE;
    size_t argc = 1;
    napi_value arg[1];
    napi_get_cb_info(env, info, &argc, arg, nullptr, nullptr);
    if (argc > 0)
    {
      napi_valuetype type;
      napi_typeof(env, arg[0], &type);

      if (type != napi_boolean)
      {
        THROW_TYPE_ERRORF(nullptr, "Argument %lu has wrong type. Should be a Boolean", 0);
      }

      bool temp;
      napi_get_value_bool(env, arg[0], &temp);
      ckTokenPresent = temp;
    }

    // Call PKCS11 function
    CK_ULONG slotCount;
    CK_RV rv = pkcs11->functionList->C_GetSlotList(ckTokenPresent, nullptr, &slotCount); // get slot count
    ASSERT_RV(rv);

    // In some cases, the pkcs11 module from Yubico may return slotCount 0 on the first call to C_GetSlotList,
    // and a non-zero value on subsequent calls. This can lead to a memory access error when using pSlotList.
    // To handle this, we check if slotCount is 0 and return an empty array if no slots are available.
    if (slotCount == 0)
    {
      napi_value result;
      napi_create_array(env, &result);
      return result;
    }

    std::vector<CK_SLOT_ID> slotList(slotCount);
    CK_SLOT_ID_PTR pSlotList = slotList.data();
    rv = pkcs11->functionList->C_GetSlotList(ckTokenPresent, pSlotList, &slotCount);
    ASSERT_RV(rv);

    // Create result array
    napi_value result;
    napi_create_array(env, &result);
    for (int i = 0; i < int(slotCount); i++)
    {
      napi_value slotId;
      napi_create_buffer_copy(env, sizeof(CK_SLOT_ID), &pSlotList[i], nullptr, &slotId);
      napi_set_element(env, result, i, slotId);
    }

    return result;
  }

  static napi_value C_GetSlotInfo(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SLOT_ID(0, slotId)

    // Call PKCS11 function
    CK_SLOT_INFO ckSlotInfo = {};
    CK_RV rv = pkcs11->functionList->C_GetSlotInfo(slotId, &ckSlotInfo);
    ASSERT_RV(rv);

    // Create result object
    napi_value result;
    napi_create_object(env, &result);

    napi_value slotDescription;
    napi_create_string_utf8(env, (char *)&ckSlotInfo.slotDescription[0], sizeof(ckSlotInfo.slotDescription), &slotDescription);
    napi_set_named_property(env, result, "slotDescription", slotDescription);

    napi_value manufacturerID;
    napi_create_string_utf8(env, (char *)&ckSlotInfo.manufacturerID[0], sizeof(ckSlotInfo.manufacturerID), &manufacturerID);
    napi_set_named_property(env, result, "manufacturerID", manufacturerID);

    napi_value flags;
    napi_create_uint32(env, ckSlotInfo.flags, &flags);
    napi_set_named_property(env, result, "flags", flags);

    napi_value hardwareVersion = create_version(env, ckSlotInfo.hardwareVersion);
    napi_set_named_property(env, result, "hardwareVersion", hardwareVersion);

    napi_value firmwareVersion = create_version(env, ckSlotInfo.firmwareVersion);
    napi_set_named_property(env, result, "firmwareVersion", firmwareVersion);

    return result;
  }

  static napi_value C_GetTokenInfo(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SLOT_ID(0, slotId)

    // Call PKCS11 function
    CK_TOKEN_INFO ckTokenInfo = {};
    CK_RV rv = pkcs11->functionList->C_GetTokenInfo(slotId, &ckTokenInfo);
    ASSERT_RV(rv);

    // Create result object
    napi_value result;
    napi_create_object(env, &result);

    // label
    napi_value label;
    napi_create_string_utf8(env, (char *)&ckTokenInfo.label[0], sizeof(ckTokenInfo.label), &label);
    napi_set_named_property(env, result, "label", label);

    // manufacturerID
    napi_value manufacturerID;
    napi_create_string_utf8(env, (char *)&ckTokenInfo.manufacturerID[0], sizeof(ckTokenInfo.manufacturerID), &manufacturerID);
    napi_set_named_property(env, result, "manufacturerID", manufacturerID);

    // model
    napi_value model;
    napi_create_string_utf8(env, (char *)&ckTokenInfo.model[0], sizeof(ckTokenInfo.model), &model);
    napi_set_named_property(env, result, "model", model);

    // serialNumber
    napi_value serialNumber;
    napi_create_string_utf8(env, (char *)&ckTokenInfo.serialNumber[0], sizeof(ckTokenInfo.serialNumber), &serialNumber);
    napi_set_named_property(env, result, "serialNumber", serialNumber);

    // flags
    napi_value flags;
    napi_create_uint32(env, ckTokenInfo.flags, &flags);
    napi_set_named_property(env, result, "flags", flags);

    // maxSessionCount
    napi_value ulMaxSessionCount;
    napi_create_uint32(env, ckTokenInfo.ulMaxSessionCount, &ulMaxSessionCount);
    napi_set_named_property(env, result, "maxSessionCount", ulMaxSessionCount);

    // sessionCount
    napi_value ulSessionCount;
    napi_create_uint32(env, ckTokenInfo.ulSessionCount, &ulSessionCount);
    napi_set_named_property(env, result, "sessionCount", ulSessionCount);

    // maxRwSessionCount
    napi_value ulMaxRwSessionCount;
    napi_create_uint32(env, ckTokenInfo.ulMaxRwSessionCount, &ulMaxRwSessionCount);
    napi_set_named_property(env, result, "maxRwSessionCount", ulMaxRwSessionCount);

    // rwSessionCount
    napi_value ulRwSessionCount;
    napi_create_uint32(env, ckTokenInfo.ulRwSessionCount, &ulRwSessionCount);
    napi_set_named_property(env, result, "rwSessionCount", ulRwSessionCount);

    // maxPinLen
    napi_value ulMaxPinLen;
    napi_create_uint32(env, ckTokenInfo.ulMaxPinLen, &ulMaxPinLen);
    napi_set_named_property(env, result, "maxPinLen", ulMaxPinLen);

    // minPinLen
    napi_value ulMinPinLen;
    napi_create_uint32(env, ckTokenInfo.ulMinPinLen, &ulMinPinLen);
    napi_set_named_property(env, result, "minPinLen", ulMinPinLen);

    // hardwareVersion
    napi_value hardwareVersion = create_version(env, ckTokenInfo.hardwareVersion);
    napi_set_named_property(env, result, "hardwareVersion", hardwareVersion);

    // firmwareVersion
    napi_value firmwareVersion = create_version(env, ckTokenInfo.firmwareVersion);
    napi_set_named_property(env, result, "firmwareVersion", firmwareVersion);

    // utcTime
    napi_value utcTime = create_date_utc_property(env, ckTokenInfo.utcTime);
    napi_set_named_property(env, result, "utcTime", utcTime);

    // totalPublicMemory
    napi_value totalPublicMemory;
    napi_create_bigint_uint64(env, ckTokenInfo.ulTotalPublicMemory, &totalPublicMemory);
    napi_set_named_property(env, result, "totalPublicMemory", totalPublicMemory);

    // freePublicMemory
    napi_value freePublicMemory;
    napi_create_bigint_uint64(env, ckTokenInfo.ulFreePublicMemory, &freePublicMemory);
    napi_set_named_property(env, result, "freePublicMemory", freePublicMemory);

    // totalPrivateMemory
    napi_value totalPrivateMemory;
    napi_create_bigint_uint64(env, ckTokenInfo.ulTotalPrivateMemory, &totalPrivateMemory);
    napi_set_named_property(env, result, "totalPrivateMemory", totalPrivateMemory);

    // freePrivateMemory
    napi_value freePrivateMemory;
    napi_create_bigint_uint64(env, ckTokenInfo.ulFreePrivateMemory, &freePrivateMemory);
    napi_set_named_property(env, result, "freePrivateMemory", freePrivateMemory);

    return result;
  }

  static napi_value C_GetMechanismList(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SLOT_ID(0, slotId)

    // Call PKCS11 function
    CK_ULONG mechanismCount;
    CK_RV rv = pkcs11->functionList->C_GetMechanismList(slotId, nullptr, &mechanismCount); // get mechanism count
    ASSERT_RV(rv);

    if (mechanismCount == 0)
    {
      napi_value result;
      napi_create_array(env, &result);
      return result;
    }

    std::vector<CK_MECHANISM_TYPE> mechanismList(mechanismCount);
    CK_MECHANISM_TYPE_PTR pMechanismList = mechanismList.data();
    rv = pkcs11->functionList->C_GetMechanismList(slotId, pMechanismList, &mechanismCount);
    ASSERT_RV(rv);

    // Create result array
    napi_value result;
    napi_create_array(env, &result);
    for (int i = 0; i < int(mechanismCount); i++)
    {
      napi_value mechanism;
      napi_create_uint32(env, pMechanismList[i], &mechanism);
      napi_set_element(env, result, i, mechanism);
    }

    return result;
  }

  static napi_value C_GetMechanismInfo(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SLOT_ID(0, slotId)
    GET_ARGS_MECHANISM_TYPE(1, mechanismType)

    // Call PKCS11 function
    CK_MECHANISM_INFO ckMechanismInfo = {};
    CK_RV rv = pkcs11->functionList->C_GetMechanismInfo(slotId, mechanismType, &ckMechanismInfo);
    ASSERT_RV(rv);

    // Create result object
    napi_value result;
    napi_create_object(env, &result);

    napi_value minKeySize;
    napi_create_uint32(env, ckMechanismInfo.ulMinKeySize, &minKeySize);
    napi_set_named_property(env, result, "minKeySize", minKeySize);

    napi_value maxKeySize;
    napi_create_uint32(env, ckMechanismInfo.ulMaxKeySize, &maxKeySize);
    napi_set_named_property(env, result, "maxKeySize", maxKeySize);

    napi_value flags;
    napi_create_uint32(env, ckMechanismInfo.flags, &flags);
    napi_set_named_property(env, result, "flags", flags);

    return result;
  }

  static napi_value C_InitToken(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SLOT_ID(0, slotId)
    GET_ARGS_STRING(1, pin)
    GET_ARGS_STRING(2, label)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_InitToken(slotId, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)pinLength, (CK_UTF8CHAR_PTR)label);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_InitPIN(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_STRING(1, pin)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_InitPIN(sessionHandle, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)pinLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_SetPIN(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_STRING(1, oldPin)
    GET_ARGS_STRING(2, newPin)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SetPIN(
        sessionHandle,
        (CK_UTF8CHAR_PTR)oldPin, (CK_ULONG)oldPinLength,
        (CK_UTF8CHAR_PTR)newPin, (CK_ULONG)newPinLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_OpenSession(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SLOT_ID(0, slotId)
    GET_ARGS_ULONG(1, flags)
    // GET_FUNCTION_FROM_ARG(2, callback)

    // Call PKCS11 function
    CK_SESSION_HANDLE sessionHandle;
    CK_RV rv = pkcs11->functionList->C_OpenSession(slotId, (CK_FLAGS)flags, nullptr, nullptr, &sessionHandle);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_buffer_copy(env, sizeof(sessionHandle), &sessionHandle, nullptr, &result);

    return result;
  }

  static napi_value C_CloseSession(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_CloseSession(sessionHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_CloseAllSessions(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SLOT_ID(0, slotId)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_CloseAllSessions(slotId);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_GetSessionInfo(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)

    // Call PKCS11 function
    CK_SESSION_INFO ckSessionInfo = {};
    CK_RV rv = pkcs11->functionList->C_GetSessionInfo(sessionHandle, &ckSessionInfo);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_object(env, &result);

    napi_value slotID;
    napi_create_buffer_copy(env, sizeof(ckSessionInfo.slotID), &ckSessionInfo.slotID, nullptr, &slotID);
    napi_set_named_property(env, result, "slotID", slotID);

    napi_value state;
    napi_create_uint32(env, ckSessionInfo.state, &state);
    napi_set_named_property(env, result, "state", state);

    napi_value flags;
    napi_create_uint32(env, ckSessionInfo.flags, &flags);
    napi_set_named_property(env, result, "flags", flags);

    napi_value ulDeviceError;
    napi_create_uint32(env, ckSessionInfo.ulDeviceError, &ulDeviceError);
    napi_set_named_property(env, result, "deviceError", ulDeviceError);

    return result;
  }

  static napi_value C_GetOperationState(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)

    // Call PKCS11 function
    CK_ULONG stateLength;
    CK_RV rv = pkcs11->functionList->C_GetOperationState(sessionHandle, nullptr, &stateLength); // get state length
    ASSERT_RV(rv);

    std::vector<CK_BYTE> stateVector(stateLength);
    CK_BYTE_PTR state = stateVector.data();
    rv = pkcs11->functionList->C_GetOperationState(sessionHandle, state, &stateLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_buffer_copy(env, stateLength, state, nullptr, &result);

    return result;
  }

  static napi_value C_SetOperationState(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, state)
    GET_ARGS_HANDLE(2, encryptionKeyHandle)
    GET_ARGS_HANDLE(3, authenticationKeyHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SetOperationState(
        sessionHandle,
        (CK_BYTE_PTR)state, (CK_ULONG)stateLength,
        (CK_OBJECT_HANDLE)encryptionKeyHandle,
        (CK_OBJECT_HANDLE)authenticationKeyHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_Login(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_ULONG(1, userType)
    GET_ARGS_STRING(2, pin)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Login(sessionHandle, (CK_USER_TYPE)userType, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)pinLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_Logout(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Logout(sessionHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_SeedRandom(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, seed)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SeedRandom(sessionHandle, (CK_BYTE_PTR)seed, (CK_ULONG)seedLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_GenerateRandom(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, randomData)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_GenerateRandom(sessionHandle, (CK_BYTE_PTR)randomData, (CK_ULONG)randomDataLength);
    ASSERT_RV(rv);

    return arg[1];
  }

  static napi_value C_CreateObject(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_ATTRIBUTES(1, attrs)

    // Call PKCS11 function
    CK_OBJECT_HANDLE objectHandle;
    CK_RV rv = pkcs11->functionList->C_CreateObject(sessionHandle, attrs.attributes, attrsLength, &objectHandle);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_buffer_copy(env, sizeof(objectHandle), &objectHandle, nullptr, &result);

    return result;
  }

  static napi_value C_FindObjectsInit(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_ATTRIBUTES(1, attrs)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_FindObjectsInit(sessionHandle, attrs.attributes, attrsLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_FindObjects(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_ULONG(1, maxObjectCount)

    // Call PKCS11 function
    CK_ULONG objectCount;
    std::vector<CK_OBJECT_HANDLE> objectVector(maxObjectCount);
    CK_OBJECT_HANDLE_PTR objectHandles = objectVector.data();
    CK_RV rv = pkcs11->functionList->C_FindObjects(sessionHandle, objectHandles, maxObjectCount, &objectCount);
    ASSERT_RV(rv);

    // Create result array
    napi_value result;
    napi_create_array(env, &result);
    for (int i = 0; i < int(objectCount); i++)
    {
      napi_value objectHandle;
      napi_create_buffer_copy(env, sizeof(objectHandles[i]), &objectHandles[i], nullptr, &objectHandle);
      napi_set_element(env, result, i, objectHandle);
    }

    return result;
  }

  static napi_value C_FindObjectsFinal(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_FindObjectsFinal(sessionHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_CopyObject(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_HANDLE(1, objectHandle)
    GET_ARGS_ATTRIBUTES(2, attrs)

    // Call PKCS11 function
    CK_OBJECT_HANDLE newObjectHandle;
    CK_RV rv = pkcs11->functionList->C_CopyObject(
        sessionHandle,
        objectHandle,
        attrs.attributes, attrsLength,
        &newObjectHandle);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_buffer_copy(env, sizeof(newObjectHandle), &newObjectHandle, nullptr, &result);

    return result;
  }

  static napi_value C_DestroyObject(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_HANDLE(1, objectHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_DestroyObject(sessionHandle, objectHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_GetAttributeValue(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_HANDLE(1, objectHandle)
    GET_ARGS_ATTRIBUTES(2, attrs)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_GetAttributeValue(sessionHandle, objectHandle, attrs.attributes, attrsLength);
    ASSERT_RV(rv);

    attrs.allocAllValues();

    rv = pkcs11->functionList->C_GetAttributeValue(sessionHandle, objectHandle, attrs.attributes, attrsLength);
    ASSERT_RV(rv);

    // Create result array
    napi_value result = arg[2];
    for (int i = 0; i < int(attrsLength); i++)
    {
      // Get element
      napi_value element;
      napi_get_element(env, result, i, &element);

      // create Buffer for value
      napi_value value;
      CK_ATTRIBUTE_PTR attr = &attrs.attributes[i];

      if (attr->ulValueLen == CK_UNAVAILABLE_INFORMATION)
      {
        napi_get_undefined(env, &value);
        napi_set_named_property(env, element, "value", value);
        continue;
      }

      if (attr->type == CKA_START_DATE || attr->type == CKA_END_DATE)
      {
        if (attr->ulValueLen != sizeof(CK_DATE))
        {
          THROW_TYPE_ERRORF(nullptr, "Attribute 0x%08lX has wrong length. Should be %lu, but is %lu", attr->type, sizeof(CK_DATE), attr->ulValueLen);
        }

        char *dateStr = (char *)malloc(9);
        CK_DATE *datePtr = (CK_DATE *)attr->pValue;
        snprintf(dateStr, 9, "%04d%02d%02d",
                 atoi((char *)datePtr->year),  // year
                 atoi((char *)datePtr->month), // month
                 atoi((char *)datePtr->day));  // day

        napi_create_buffer_copy(env, 8, dateStr, nullptr, &value);
        free(dateStr);
        napi_set_named_property(env, element, "value", value);

        continue;
      }

      napi_create_buffer_copy(env, attr->ulValueLen, attr->pValue, nullptr, &value);

      // set value property on element
      napi_set_named_property(env, element, "value", value);
    }

    return result;
  }

  static napi_value C_SetAttributeValue(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_HANDLE(1, objectHandle)
    GET_ARGS_ATTRIBUTES(2, attrs)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SetAttributeValue(sessionHandle, objectHandle, attrs.attributes, attrsLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_GetObjectSize(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_HANDLE(1, objectHandle)

    // Call PKCS11 function
    CK_ULONG objectSize;
    CK_RV rv = pkcs11->functionList->C_GetObjectSize(sessionHandle, objectHandle, &objectSize);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_uint32(env, objectSize, &result);

    return result;
  }

  static napi_value C_DigestInit(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_DigestInit(sessionHandle, mechanism.value);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_Digest(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, digest)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Digest(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)digest, (CK_ULONG_PTR)&digestLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_uint32(env, digestLength, &result);

    return result;
  }

  static napi_value C_DigestCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, digest)
    GET_ARGS_CALLBACK(3, callback)

    // Create worker
    new Worker(env, callback, pkcs11->functionList->C_Digest, sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)digest, (CK_ULONG)digestLength);
    return nullptr;
  }

  static napi_value C_DigestUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_DigestUpdate(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_DigestKey(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_HANDLE(1, keyHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_DigestKey(sessionHandle, keyHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_DigestFinal(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, digest)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_DigestFinal(sessionHandle, (CK_BYTE_PTR)digest, (CK_ULONG_PTR)&digestLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_uint32(env, digestLength, &result);

    return result;
  }

  static napi_value C_DigestFinalCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, digest)
    GET_ARGS_CALLBACK(2, callback)

    // Create worker
    new Worker2(env, callback, pkcs11->functionList->C_DigestFinal, sessionHandle, (CK_BYTE_PTR)digest, (CK_ULONG)digestLength);
    return nullptr;
  }

  static napi_value C_GenerateKey(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_ATTRIBUTES(2, attrs)

    // Call PKCS11 function
    CK_OBJECT_HANDLE keyHandle;
    CK_RV rv = pkcs11->functionList->C_GenerateKey(sessionHandle, mechanism.value, attrs.attributes, attrsLength, &keyHandle);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_buffer_copy(env, sizeof(keyHandle), &keyHandle, nullptr, &result);

    return result;
  }

  static napi_value C_GenerateKeyCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    mechanism.dispose = false;
    GET_ARGS_ATTRIBUTES(2, attrs)
    attrs.dispose = false;
    GET_ARGS_CALLBACK(3, callback)

    // Create worker
    new WorkerGenerateKey(env, callback, pkcs11->functionList->C_GenerateKey, sessionHandle, mechanism.value, attrs.attributes, attrsLength);
    return nullptr;
  }

  static napi_value C_GenerateKeyPair(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_ATTRIBUTES(2, publicKeyAttrs)
    GET_ARGS_ATTRIBUTES(3, privateKeyAttrs)

    // Call PKCS11 function
    CK_OBJECT_HANDLE publicKeyHandle;
    CK_OBJECT_HANDLE privateKeyHandle;
    CK_RV rv = pkcs11->functionList->C_GenerateKeyPair(
        sessionHandle,
        mechanism.value,
        publicKeyAttrs.attributes, publicKeyAttrsLength,
        privateKeyAttrs.attributes, privateKeyAttrsLength,
        &publicKeyHandle, &privateKeyHandle);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_object(env, &result);

    napi_value privateKey;
    napi_create_buffer_copy(env, sizeof(privateKeyHandle), &privateKeyHandle, nullptr, &privateKey);
    napi_set_named_property(env, result, "privateKey", privateKey);

    napi_value publicKey;
    napi_create_buffer_copy(env, sizeof(publicKeyHandle), &publicKeyHandle, nullptr, &publicKey);
    napi_set_named_property(env, result, "publicKey", publicKey);

    return result;
  }

  static napi_value C_GenerateKeyPairCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(5, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    mechanism.dispose = false;
    GET_ARGS_ATTRIBUTES(2, publicKeyAttrs)
    publicKeyAttrs.dispose = false;
    GET_ARGS_ATTRIBUTES(3, privateKeyAttrs)
    privateKeyAttrs.dispose = false;
    GET_ARGS_CALLBACK(4, callback)

    new WorkerGenerateKeyPair(env, callback, pkcs11->functionList->C_GenerateKeyPair, sessionHandle, mechanism.value, publicKeyAttrs.attributes, publicKeyAttrsLength, privateKeyAttrs.attributes, privateKeyAttrsLength);
    return nullptr;
  }

  static napi_value C_SignInit(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, keyHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SignInit(sessionHandle, mechanism.value, keyHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_Sign(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, signature)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Sign(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)signature, (CK_ULONG_PTR)&signatureLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_uint32(env, signatureLength, &result);

    return result;
  }

  static napi_value C_SignCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, signature)
    GET_ARGS_CALLBACK(3, callback)

    // Create worker
    new Worker(env, callback, pkcs11->functionList->C_Sign, sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)signature, (CK_ULONG)signatureLength);
    return nullptr;
  }

  static napi_value C_SignUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SignUpdate(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_SignFinal(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, signature)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SignFinal(sessionHandle, (CK_BYTE_PTR)signature, (CK_ULONG_PTR)&signatureLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_uint32(env, signatureLength, &result);

    return result;
  }

  static napi_value C_SignFinalCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, signature)
    GET_ARGS_CALLBACK(2, callback)

    // Create worker
    new Worker2(env, callback, pkcs11->functionList->C_SignFinal, sessionHandle, (CK_BYTE_PTR)signature, (CK_ULONG)signatureLength);
    return nullptr;
  }

  static napi_value C_VerifyInit(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, keyHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_VerifyInit(sessionHandle, mechanism.value, keyHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_Verify(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, signature)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Verify(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)signature, (CK_ULONG)signatureLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_get_boolean(env, true, &result);

    return result;
  }

  static napi_value C_VerifyCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, signature)
    GET_ARGS_CALLBACK(3, callback)

    // Create worker
    new WorkerVerify(env, callback, pkcs11->functionList->C_Verify, sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)signature, (CK_ULONG)signatureLength);
    return nullptr;
  }

  static napi_value C_VerifyUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_VerifyUpdate(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_VerifyFinal(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, signature)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_VerifyFinal(sessionHandle, (CK_BYTE_PTR)signature, (CK_ULONG)signatureLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_get_boolean(env, true, &result);

    return result;
  }

  static napi_value C_VerifyFinalCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, signature)
    GET_ARGS_CALLBACK(2, callback)

    // Create worker
    new WorkerVerifyFinal(env, callback, pkcs11->functionList->C_VerifyFinal, sessionHandle, (CK_BYTE_PTR)signature, (CK_ULONG)signatureLength);
    return nullptr;
  }

  static napi_value C_EncryptInit(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, keyHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_EncryptInit(sessionHandle, mechanism.value, keyHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_Encrypt(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, encryptedData)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Encrypt(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)encryptedData, (CK_ULONG_PTR)&encryptedDataLength);
    ASSERT_RV(rv);

    // Create result (size of encryptedData)
    napi_value result;
    napi_create_uint32(env, encryptedDataLength, &result);

    return result;
  }

  static napi_value C_EncryptCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, encryptedData)
    GET_ARGS_CALLBACK(3, callback)

    new Worker(env, callback, pkcs11->functionList->C_Encrypt, sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)encryptedData, (CK_ULONG)encryptedDataLength);
    return nullptr;
  }

  static napi_value C_EncryptUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, encryptedData)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_EncryptUpdate(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)encryptedData, (CK_ULONG_PTR)&encryptedDataLength);
    ASSERT_RV(rv);

    // Create result (size of encryptedData)
    napi_value result;
    napi_create_uint32(env, encryptedDataLength, &result);

    return result;
  }

  static napi_value C_EncryptFinal(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, encryptedData)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_EncryptFinal(sessionHandle, (CK_BYTE_PTR)encryptedData, (CK_ULONG_PTR)&encryptedDataLength);
    ASSERT_RV(rv);

    // Create result (size of encryptedData)
    napi_value result;
    napi_create_uint32(env, encryptedDataLength, &result);

    return result;
  }

  static napi_value C_EncryptFinalCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, encryptedData)
    GET_ARGS_CALLBACK(2, callback)

    // Create worker
    new Worker2(env, callback, pkcs11->functionList->C_EncryptFinal, sessionHandle, (CK_BYTE_PTR)encryptedData, (CK_ULONG)encryptedDataLength);
    return nullptr;
  }

  static napi_value C_DecryptInit(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, keyHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_DecryptInit(sessionHandle, mechanism.value, keyHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_Decrypt(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, encryptedData)
    GET_ARGS_BUFFER(2, data)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_Decrypt(sessionHandle, (CK_BYTE_PTR)encryptedData, (CK_ULONG)encryptedDataLength, (CK_BYTE_PTR)data, (CK_ULONG_PTR)&dataLength);
    ASSERT_RV(rv);

    // Create result (size of data)
    napi_value result;
    napi_create_uint32(env, dataLength, &result);

    return result;
  }

  static napi_value C_DecryptCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, encryptedData)
    GET_ARGS_BUFFER(2, data)
    GET_ARGS_CALLBACK(3, callback)

    // Create worker
    new Worker(env, callback, pkcs11->functionList->C_Decrypt, sessionHandle, (CK_BYTE_PTR)encryptedData, (CK_ULONG)encryptedDataLength, (CK_BYTE_PTR)data, (CK_ULONG)dataLength);
    return nullptr;
  }

  static napi_value C_DecryptUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, encryptedData)
    GET_ARGS_BUFFER(2, data)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_DecryptUpdate(sessionHandle, (CK_BYTE_PTR)encryptedData, (CK_ULONG)encryptedDataLength, (CK_BYTE_PTR)data, (CK_ULONG_PTR)&dataLength);
    ASSERT_RV(rv);

    // Create result (size of data)
    napi_value result;
    napi_create_uint32(env, dataLength, &result);

    return result;
  }

  static napi_value C_DecryptFinal(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(2, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_DecryptFinal(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG_PTR)&dataLength);
    ASSERT_RV(rv);

    // Create result (size of data)
    napi_value result;
    napi_create_uint32(env, dataLength, &result);

    return result;
  }

  static napi_value C_DecryptFinalCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_CALLBACK(2, callback)

    // Create worker
    new Worker2(env, arg[2], pkcs11->functionList->C_DecryptFinal, sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength);
    return nullptr;
  }

  static napi_value C_DeriveKey(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, baseKeyHandle)
    GET_ARGS_ATTRIBUTES(3, attrs)

    // Call PKCS11 function
    CK_OBJECT_HANDLE keyHandle;
    CK_RV rv = pkcs11->functionList->C_DeriveKey(sessionHandle, mechanism.value, baseKeyHandle, attrs.attributes, attrsLength, &keyHandle);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_buffer_copy(env, sizeof(keyHandle), &keyHandle, nullptr, &result);

    return result;
  }

  static napi_value C_DeriveKeyCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(5, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    mechanism.dispose = false;
    GET_ARGS_HANDLE(2, baseKeyHandle)
    GET_ARGS_ATTRIBUTES(3, attrs)
    attrs.dispose = false;
    GET_ARGS_CALLBACK(4, callback)

    // Create worker
    new WorkerDeriveKey(env, callback, pkcs11->functionList->C_DeriveKey, sessionHandle, mechanism.value, baseKeyHandle, attrs.attributes, attrsLength);
    return nullptr;
  }

  static napi_value C_WrapKey(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(5, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, wrappingKeyHandle)
    GET_ARGS_HANDLE(3, keyHandle)
    GET_ARGS_BUFFER(4, wrappedKey)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_WrapKey(sessionHandle, mechanism.value, wrappingKeyHandle, keyHandle, (CK_BYTE_PTR)wrappedKey, (CK_ULONG_PTR)&wrappedKeyLength);
    ASSERT_RV(rv);

    // Create result (size of wrappedKey)
    napi_value result;
    napi_create_uint32(env, wrappedKeyLength, &result);

    return result;
  }

  static napi_value C_WrapKeyCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(6, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    mechanism.dispose = false;
    GET_ARGS_HANDLE(2, wrappingKeyHandle)
    GET_ARGS_HANDLE(3, keyHandle)
    GET_ARGS_BUFFER(4, wrappedKey)
    GET_ARGS_CALLBACK(5, callback)

    // Create worker
    new WorkerWrapKey(env, callback, pkcs11->functionList->C_WrapKey, sessionHandle, mechanism.value, wrappingKeyHandle, keyHandle, (CK_BYTE_PTR)wrappedKey, (CK_ULONG)wrappedKeyLength);
    return nullptr;
  }

  static napi_value C_UnwrapKey(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(5, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, unwrappingKeyHandle)
    GET_ARGS_BUFFER(3, wrappedKey)
    GET_ARGS_ATTRIBUTES(4, attrs)

    // Call PKCS11 function
    CK_OBJECT_HANDLE keyHandle;
    CK_RV rv = pkcs11->functionList->C_UnwrapKey(sessionHandle, mechanism.value, unwrappingKeyHandle, (CK_BYTE_PTR)wrappedKey, (CK_ULONG)wrappedKeyLength, attrs.attributes, attrsLength, &keyHandle);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_buffer_copy(env, sizeof(keyHandle), &keyHandle, nullptr, &result);

    return result;
  }

  static napi_value C_UnwrapKeyCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(6, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    mechanism.dispose = false;
    GET_ARGS_HANDLE(2, unwrappingKeyHandle)
    GET_ARGS_BUFFER(3, wrappedKey)
    GET_ARGS_ATTRIBUTES(4, attrs)
    attrs.dispose = false;
    GET_ARGS_CALLBACK(5, callback)

    // Create worker
    new WorkerUnwrapKey(env, callback, pkcs11->functionList->C_UnwrapKey, sessionHandle, mechanism.value, unwrappingKeyHandle, (CK_BYTE_PTR)wrappedKey, (CK_ULONG)wrappedKeyLength, attrs.attributes, attrsLength);
    return nullptr;
  }

  static napi_value C_SignRecoverInit(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, keyHandle)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SignRecoverInit(sessionHandle, mechanism.value, keyHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_SignRecover(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, data)
    GET_ARGS_BUFFER(2, signature)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_SignRecover(sessionHandle, (CK_BYTE_PTR)data, (CK_ULONG)dataLength, (CK_BYTE_PTR)signature, (CK_ULONG_PTR)&signatureLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_uint32(env, signatureLength, &result);

    return result;
  }

  static napi_value C_VerifyRecoverInit(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_MECHANISM(1, mechanism)
    GET_ARGS_HANDLE(2, keyHandle)

    CK_RV rv = pkcs11->functionList->C_VerifyRecoverInit(sessionHandle, mechanism.value, keyHandle);
    ASSERT_RV(rv);

    return nullptr;
  }

  static napi_value C_VerifyRecover(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, signature)
    GET_ARGS_BUFFER(2, data)

    // Call PKCS11 function
    CK_RV rv = pkcs11->functionList->C_VerifyRecover(sessionHandle, (CK_BYTE_PTR)signature, (CK_ULONG)signatureLength, (CK_BYTE_PTR)data, (CK_ULONG_PTR)&dataLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_uint32(env, dataLength, &result);

    return result;
  }

  static napi_value C_WaitForSlotEvent(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();
    GET_ARGS(1, arg)

    // Read arguments
    GET_ARGS_ULONG(0, flags)

    // Call PKCS11 function
    CK_SLOT_ID slotId;
    CK_RV rv = pkcs11->functionList->C_WaitForSlotEvent(flags, &slotId, nullptr);
    if (rv != CKR_NO_EVENT)
    {
      ASSERT_RV(rv);
    }

    // Create result
    napi_value result;
    if (rv == CKR_NO_EVENT)
    {
      napi_get_null(env, &result);
    }
    else
    {
      napi_create_buffer_copy(env, sizeof(CK_SLOT_ID), &slotId, nullptr, &result);
    }
    return result;
  }

  static napi_value dualOperation(napi_env env, napi_callback_info info, CK_C_DigestEncryptUpdate operation)
  {
    UNWRAP_PKCS11();
    GET_ARGS(3, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, inData)
    GET_ARGS_BUFFER(2, outData)

    // Call PKCS11 function
    CK_RV rv = operation(sessionHandle, (CK_BYTE_PTR)inData, (CK_ULONG)inDataLength, (CK_BYTE_PTR)outData, (CK_ULONG_PTR)&outDataLength);
    ASSERT_RV(rv);

    // Create result
    napi_value result;
    napi_create_uint32(env, outDataLength, &result);

    return result;
  }

  static napi_value dualOperationCallback(napi_env env, napi_callback_info info, CK_C_DigestEncryptUpdate operation)
  {
    UNWRAP_PKCS11();
    GET_ARGS(4, arg)

    // Read arguments
    GET_ARGS_SESSION_HANDLE(0, sessionHandle)
    GET_ARGS_BUFFER(1, inData)
    GET_ARGS_BUFFER(2, outData)
    GET_ARGS_CALLBACK(3, callback)

    // Create worker
    new WorkerDualOperation(env, callback, operation, sessionHandle, (CK_BYTE_PTR)inData, (CK_ULONG)inDataLength, (CK_BYTE_PTR)outData, (CK_ULONG)outDataLength);
    return nullptr;
  }

  static napi_value C_DigestEncryptUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    return dualOperation(env, info, pkcs11->functionList->C_DigestEncryptUpdate);
  }

  static napi_value C_DigestEncryptUpdateCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    return dualOperationCallback(env, info, pkcs11->functionList->C_DigestEncryptUpdate);
  }

  static napi_value C_DecryptDigestUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    return dualOperation(env, info, pkcs11->functionList->C_DecryptDigestUpdate);
  }

  static napi_value C_DecryptDigestUpdateCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    return dualOperationCallback(env, info, pkcs11->functionList->C_DecryptDigestUpdate);
  }

  static napi_value C_SignEncryptUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    return dualOperation(env, info, pkcs11->functionList->C_SignEncryptUpdate);
  }

  static napi_value C_SignEncryptUpdateCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    return dualOperationCallback(env, info, pkcs11->functionList->C_SignEncryptUpdate);
  }

  static napi_value C_DecryptVerifyUpdate(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    return dualOperation(env, info, pkcs11->functionList->C_DecryptVerifyUpdate);
  }

  static napi_value C_DecryptVerifyUpdateCallback(napi_env env, napi_callback_info info)
  {
    UNWRAP_PKCS11();

    return dualOperationCallback(env, info, pkcs11->functionList->C_DecryptVerifyUpdate);
  }
};
