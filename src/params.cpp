/**
 * @file params.cpp
 * @brief This file contains functions for reading and retrieving mechanism parameters.
 */
#include "common.h"

/**
 * @brief Macro for throwing a type error if a property of a mechanism parameter is not of the expected type.
 *
 * @param property The name of the property.
 * @param paramType The type of the mechanism parameter.
 * @param type The name of the mechanism parameter type.
 */
#define THROW_PROPERTY_TYPE(property, paramType, type) \
  THROW_TYPE_ERRORF(false, "Property '%s' of %s mechanism parameter should be %s", property, paramType, type);

/**
 * Checks if the given object has a specified property.
 *
 * @param env The N-API environment.
 * @param object The N-API value representing the object to check.
 * @param property The name of the property to check for.
 * @return True if the object has the specified property, false otherwise.
 */
bool has_property(napi_env env, napi_value object, const char *property)
{
  napi_value propertyValue;
  napi_get_named_property(env, object, property, &propertyValue);
  return !is_empty(env, propertyValue);
}

/**
 * @brief Reads a boolean property from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param object The JavaScript object to read the property from.
 * @param property The name of the property to read.
 * @param value A pointer to store the read value.
 * @return Returns true if the property was successfully read, false otherwise.
 */
bool read_property_bool(napi_env env, napi_value object, const char *property, CK_BBOOL *value)
{
  // Get the property value
  napi_value propertyValue;
  napi_get_named_property(env, object, property, &propertyValue);

  // Check that the property value is a boolean
  napi_valuetype propertyValueType;
  napi_typeof(env, propertyValue, &propertyValueType);
  if (propertyValueType != napi_boolean)
  {
    return false;
  }

  // Read the property value
  bool boolValue;
  napi_get_value_bool(env, propertyValue, &boolValue);
  *value = boolValue ? CK_TRUE : CK_FALSE;

  return true;
}

/**
 * @brief Macro for reading a required boolean property from a given JavaScript object.
 *
 * Creates a variable with the name of the property and reads the property value into it.
 *
 * @param property The name of the property to read.
 * @param target The JavaScript object to read the property from.
 * @param paramType The type of the mechanism parameter.
 */
#define READ_BOOL_REQUIRED(property, target, paramType)       \
  CK_BBOOL property;                                          \
  if (!read_property_bool(env, target, #property, &property)) \
  {                                                           \
    THROW_PROPERTY_TYPE(#property, #paramType, "Boolean");    \
  }

/**
 * @brief Macro for reading an optional boolean property from a given JavaScript object.
 *
 * Creates a variable with the name of the property and reads the property value into it
 * if the property exists, otherwise the variable is set to CK_FALSE.
 *
 * @param property The name of the property to read.
 * @param target The JavaScript object to read the property from.
 * @param paramType The type of the mechanism parameter.
 */
#define READ_BOOL_OPTIONAL(property, target, paramType)         \
  CK_BBOOL property = CK_FALSE;                                 \
  if (has_property(env, target, #property))                     \
  {                                                             \
    if (!read_property_bool(env, target, #property, &property)) \
    {                                                           \
      THROW_PROPERTY_TYPE(#property, #paramType, "Boolean");    \
    }                                                           \
  }

/**
 * @brief Reads an unsigned long property from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param object The JavaScript object to read the property from.
 * @param property The name of the property to read.
 * @param value A pointer to store the read value.
 * @return Returns true if the property was successfully read, false otherwise.
 */
bool read_property_ulong(napi_env env, napi_value object, const char *property, CK_ULONG *value)
{
  // Get the property value
  napi_value propertyValue;
  napi_get_named_property(env, object, property, &propertyValue);

  // Check that the property value is a number
  napi_valuetype propertyValueType;
  napi_typeof(env, propertyValue, &propertyValueType);
  if (propertyValueType != napi_number)
  {
    return false;
  }

  // Read the property value
  double doubleValue;
  napi_get_value_double(env, propertyValue, &doubleValue);
  *value = (CK_ULONG)doubleValue;

  return true;
}

/**
 * @brief Macro for reading a required unsigned long property from a given JavaScript object.
 *
 * Creates a variable with the name of the property and reads the property value into it.
 *
 * @param property The name of the property to read.
 * @param target The JavaScript object to read the property from.
 * @param paramType The type of the mechanism parameter.
 */
#define READ_ULONG_REQUIRED(property, target, paramType)       \
  CK_ULONG property = 0;                                       \
  if (!read_property_ulong(env, target, #property, &property)) \
  {                                                            \
    THROW_PROPERTY_TYPE(#property, #paramType, "Number");      \
  }

/**
 * @brief Macro for reading an optional unsigned long property from a given JavaScript object.
 *
 * Creates a variable with the name of the property and reads the property value into it
 * if the property exists, otherwise the variable is set to 0.
 *
 * @param property The name of the property to read.
 * @param target The JavaScript object to read the property from.
 * @param paramType The type of the mechanism parameter.
 */
#define READ_ULONG_OPTIONAL(property, target, paramType)         \
  CK_ULONG property = 0;                                         \
  if (has_property(env, target, #property))                      \
  {                                                              \
    if (!read_property_ulong(env, target, #property, &property)) \
    {                                                            \
      THROW_PROPERTY_TYPE(#property, #paramType, "Number");      \
    }                                                            \
  }

/**
 * @brief Reads a byte property from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param object The JavaScript object to read the property from.
 * @param property The name of the property to read.
 * @param value A pointer to store the read value.
 * @return Returns true if the property was successfully read, false otherwise.
 */
bool read_property_byte(napi_env env, napi_value object, const char *property, CK_BYTE_PTR value)
{
  // Get the property value
  napi_value propertyValue;
  napi_get_named_property(env, object, property, &propertyValue);

  // Check that the property value is a Number
  napi_valuetype propertyValueType;
  napi_typeof(env, propertyValue, &propertyValueType);
  if (propertyValueType != napi_number)
  {
    return false;
  }

  // Read the property value and write it to the single byte
  uint32_t uintValue = 0;
  napi_get_value_uint32(env, propertyValue, &uintValue);
  if (uintValue > 255)
  {
    return false;
  }
  *value = (CK_BYTE)uintValue;

  return true;
}

/**
 * @brief Macro for reading a required byte property from a given JavaScript object.
 *
 * Creates a variable with the name of the property and reads the property value into it.
 *
 * @param property The name of the property to read.
 * @param target The JavaScript object to read the property from.
 * @param paramType The type of the mechanism parameter.
 */
#define READ_BYTE_REQUIRED(property, target, paramType)       \
  CK_BYTE property;                                           \
  if (!read_property_byte(env, target, #property, &property)) \
  {                                                           \
    THROW_PROPERTY_TYPE(#property, #paramType, "Number");     \
  }

/**
 * @brief Macro for reading an optional byte property from a given JavaScript object.
 *
 * Creates a variable with the name of the property and reads the property value into it
 *
 * @param property The name of the property to read.
 * @param target The JavaScript object to read the property from.
 * @param paramType The type of the mechanism parameter.
 */
#define READ_BYTE_OPTIONAL(property, target, paramType)         \
  CK_BYTE property = 0;                                         \
  if (has_property(env, target, #property))                     \
  {                                                             \
    if (!read_property_byte(env, target, #property, &property)) \
    {                                                           \
      THROW_PROPERTY_TYPE(#property, #paramType, "Number");     \
    }                                                           \
  }

/**
 * @brief Reads a byte array property from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param object The JavaScript object to read the property from.
 * @param property The name of the property to read.
 * @param value A pointer to store the read value.
 * @param length A pointer to store the length of the read value.
 * @return Returns true if the property was successfully read, false otherwise.
 */
bool read_property_bytes(napi_env env, napi_value object, const char *property, CK_BYTE_PTR *value, CK_ULONG_PTR length)
{
  // Get the property value
  napi_value propertyValue;
  napi_get_named_property(env, object, property, &propertyValue);

  // Check that the property value is a buffer
  bool isBuffer;
  napi_is_buffer(env, propertyValue, &isBuffer);
  if (!isBuffer)
  {
    return false;
  }

  // Read the property value
  void *data;
  size_t dataLength;
  napi_get_buffer_info(env, propertyValue, &data, &dataLength);
  *value = (CK_BYTE_PTR)data;
  *length = dataLength;

  return true;
}

/**
 * @brief Macro for reading a required byte array property from a given JavaScript object.
 *
 * Creates two variables with the name of the property and reads the property value into them
 * (one for the data <property> and one for the length <property>Length).
 *
 * @param property The name of the property to read.
 * @param target The JavaScript object to read the property from.
 * @param paramType The type of the mechanism parameter.
 */
#define READ_BYTES_REQUIRED(property, target, paramType)                          \
  CK_BYTE_PTR property;                                                           \
  CK_ULONG property##Length;                                                      \
  if (!read_property_bytes(env, target, #property, &property, &property##Length)) \
  {                                                                               \
    THROW_PROPERTY_TYPE(#property, #paramType, "Buffer");                         \
  }

/**
 * @brief Macro for reading an optional byte array property from a given JavaScript object.
 *
 * Creates two variables with the name of the property and reads the property value into them
 * (one for the data <property> and one for the length <property>Length). If the property does
 * not exist, the variables are set to nullptr and 0 respectively.
 *
 * @param property The name of the property to read.
 * @param target The JavaScript object to read the property from.
 * @param paramType The type of the mechanism parameter.
 */
#define READ_BYTES_OPTIONAL(property, target, paramType)                            \
  CK_BYTE_PTR property = nullptr;                                                   \
  CK_ULONG property##Length = 0;                                                    \
  if (has_property(env, target, #property))                                         \
  {                                                                                 \
    if (!read_property_bytes(env, target, #property, &property, &property##Length)) \
    {                                                                               \
      THROW_PROPERTY_TYPE(#property, #paramType, "Buffer");                         \
    }                                                                               \
  }

bool read_property_handle(napi_env env, napi_value object, const char *property, CK_ULONG_PTR value)
{
  // Get the property value
  napi_value propertyValue;
  napi_get_named_property(env, object, property, &propertyValue);

  // Check that the property value is a Buffer
  bool isBuffer;
  napi_is_buffer(env, propertyValue, &isBuffer);
  if (!isBuffer)
  {
    return false;
  }

  // Read the property value
  void *data;
  size_t dataLength;
  napi_get_buffer_info(env, propertyValue, &data, &dataLength);
  if (dataLength != sizeof(CK_OBJECT_HANDLE))
  {
    return false;
  }
  *value = *(CK_ULONG_PTR)data;

  return true;
}

#define READ_HANDLE_REQUIRED(property, target, paramType)       \
  CK_ULONG property;                                            \
  if (!read_property_handle(env, target, #property, &property)) \
  {                                                             \
    THROW_PROPERTY_TYPE(#property, #paramType, "Buffer");       \
  }

#define READ_HANDLE_OPTIONAL(property, target, paramType)         \
  CK_ULONG property = 0;                                          \
  if (has_property(env, target, #property))                       \
  {                                                               \
    if (!read_property_handle(env, target, #property, &property)) \
    {                                                             \
      THROW_PROPERTY_TYPE(#property, #paramType, "Buffer");       \
    }                                                             \
  }

bool read_property_string(napi_env env, napi_value object, const char *property, std::string *value)
{
  // Get the property value
  napi_value propertyValue;
  napi_get_named_property(env, object, property, &propertyValue);

  // Check that the property value is a String
  napi_valuetype propertyValueType;
  napi_typeof(env, propertyValue, &propertyValueType);
  if (propertyValueType != napi_string)
  {
    return false;
  }

  // Read the property value
  size_t stringLength;
  napi_get_value_string_utf8(env, propertyValue, nullptr, 0, &stringLength);
  char *stringValue = (char *)malloc(stringLength + 1);
  napi_get_value_string_utf8(env, propertyValue, stringValue, stringLength + 1, &stringLength);
  *value = std::string(stringValue);
  free(stringValue);

  return true;
}

#define READ_STRING_REQUIRED(property, target, paramType)       \
  std::string property;                                         \
  if (!read_property_string(env, target, #property, &property)) \
  {                                                             \
    THROW_PROPERTY_TYPE(#property, #paramType, "String");       \
  }

#define READ_STRING_OPTIONAL(property, target, paramType)         \
  std::string property;                                           \
  if (has_property(env, target, #property))                       \
  {                                                               \
    if (!read_property_string(env, target, #property, &property)) \
    {                                                             \
      THROW_PROPERTY_TYPE(#property, #paramType, "String");       \
    }                                                             \
  }

/**
 * Reads CK_RSA_PKCS_OAEP_PARAMS from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param mechanismParameter The mechanism parameter value.
 * @param mechanism The CK_MECHANISM_PTR structure to store the retrieved parameters.
 * @return true if the parameters were successfully retrieved, false otherwise.
 */
bool get_params_rsa_oaep(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(hashAlg, mechanismParameter, CK_RSA_PKCS_OAEP_PARAMS);
  READ_ULONG_REQUIRED(mgf, mechanismParameter, CK_RSA_PKCS_OAEP_PARAMS);
  READ_ULONG_REQUIRED(source, mechanismParameter, CK_RSA_PKCS_OAEP_PARAMS);
  READ_BYTES_OPTIONAL(sourceData, mechanismParameter, CK_RSA_PKCS_OAEP_PARAMS);

  // Create the mechanism parameters structure
  CK_RSA_PKCS_OAEP_PARAMS_PTR params = CK_RSA_PKCS_OAEP_PARAMS_PTR(malloc(sizeof(CK_RSA_PKCS_OAEP_PARAMS)));
  params->hashAlg = hashAlg;
  params->mgf = mgf;
  params->source = source;
  params->pSourceData = sourceData;
  params->ulSourceDataLen = sourceDataLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);

  return true;
}

/**
 * Reads CK_ECDH1_DERIVE_PARAMS from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param mechanismParameter The mechanism parameter value.
 * @param mechanism The CK_MECHANISM_PTR structure to store the retrieved parameters.
 * @return true if the parameters were successfully retrieved, false otherwise.
 */
bool get_params_ec_dh(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(kdf, mechanismParameter, CK_ECDH1_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_ECDH1_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(sharedData, mechanismParameter, CK_ECDH1_DERIVE_PARAMS);

  // Create the mechanism parameters structure
  CK_ECDH1_DERIVE_PARAMS_PTR params = CK_ECDH1_DERIVE_PARAMS_PTR(malloc(sizeof(CK_ECDH1_DERIVE_PARAMS)));
  params->kdf = kdf;
  params->pSharedData = sharedData;
  params->ulSharedDataLen = sharedDataLength;
  params->pPublicData = publicData;
  params->ulPublicDataLen = publicDataLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);

  return true;
}

/**
 * Reads CK_AES_CBC_ENCRYPT_DATA_PARAMS from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param mechanismParameter The mechanism parameter value.
 * @param mechanism The CK_MECHANISM_PTR structure to store the retrieved parameters.
 * @return true if the parameters were successfully retrieved, false otherwise.
 */
bool get_params_aes_cbc(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_BYTES_REQUIRED(iv, mechanismParameter, CK_AES_CBC_ENCRYPT_DATA_PARAMS);
  READ_BYTES_OPTIONAL(data, mechanismParameter, CK_AES_CBC_ENCRYPT_DATA_PARAMS);
  if (ivLength != 16)
  {
    THROW_TYPE_ERRORF(false, "Property 'iv' of %s mechanism parameter should be a Buffer of length 16", "CK_AES_CBC_ENCRYPT_DATA_PARAMS");
  }

  // Create the mechanism parameters structure
  CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR params = CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(malloc(sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS)));
  memcpy(params->iv, iv, 16);
  params->pData = data;
  params->length = dataLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS);

  return true;
}

/**
 * Reads CK_AES_CCM_PARAMS from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param mechanismParameter The mechanism parameter value.
 * @param mechanism The CK_MECHANISM_PTR structure to store the retrieved parameters.
 * @return true if the parameters were successfully retrieved, false otherwise.
 */
bool get_params_aes_ccm(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(dataLength, mechanismParameter, CK_AES_CCM_PARAMS);
  READ_BYTES_OPTIONAL(nonce, mechanismParameter, CK_AES_CCM_PARAMS);
  READ_BYTES_OPTIONAL(aad, mechanismParameter, CK_AES_CCM_PARAMS);
  READ_ULONG_OPTIONAL(macLength, mechanismParameter, CK_AES_CCM_PARAMS);

  // Create the mechanism parameters structure
  CK_AES_CCM_PARAMS_PTR params = CK_AES_CCM_PARAMS_PTR(malloc(sizeof(CK_AES_CCM_PARAMS)));
  params->ulDataLen = dataLength;
  params->pNonce = nonce;
  params->ulNonceLen = nonceLength;
  params->pAAD = aad;
  params->ulAADLen = aadLength;
  params->ulMACLen = macLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_AES_CCM_PARAMS);

  return true;
}

/**
 * Reads CK_AES_GCM_PARAMS from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param mechanismParameter The mechanism parameter value.
 * @param mechanism The CK_MECHANISM_PTR structure to store the retrieved parameters.
 * @return true if the parameters were successfully retrieved, false otherwise.
 */
bool get_params_aes_gcm(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_BYTES_REQUIRED(iv, mechanismParameter, CK_AES_GCM_PARAMS);
  READ_BYTES_OPTIONAL(aad, mechanismParameter, CK_AES_GCM_PARAMS);
  READ_ULONG_OPTIONAL(tagBits, mechanismParameter, CK_AES_GCM_PARAMS);

  // Create the mechanism parameters structure
  CK_AES_GCM_PARAMS_PTR params = CK_AES_GCM_PARAMS_PTR(malloc(sizeof(CK_AES_GCM_PARAMS)));
  params->pIv = iv;
  params->ulIvLen = ivLength;
  params->pAAD = aad;
  params->ulAADLen = aadLength;
  params->ulTagBits = tagBits;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_AES_GCM_PARAMS);

  return true;
}

/**
 * Reads CK_AES_GCM_240_PARAMS from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param mechanismParameter The mechanism parameter value.
 * @param mechanism The CK_MECHANISM_PTR structure to store the retrieved parameters.
 * @return true if the parameters were successfully retrieved, false otherwise.
 */
bool get_params_aes_gcm_240(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_BYTES_REQUIRED(iv, mechanismParameter, CK_AES_GCM_240_PARAMS);
  READ_ULONG_REQUIRED(ivBits, mechanismParameter, CK_AES_GCM_240_PARAMS);
  READ_BYTES_OPTIONAL(aad, mechanismParameter, CK_AES_GCM_240_PARAMS);
  READ_ULONG_OPTIONAL(tagBits, mechanismParameter, CK_AES_GCM_240_PARAMS);

  // Create the mechanism parameters structure
  CK_AES_GCM_240_PARAMS_PTR params = CK_AES_GCM_240_PARAMS_PTR(malloc(sizeof(CK_AES_GCM_240_PARAMS)));
  params->pIv = iv;
  params->ulIvLen = ivLength;
  params->ulIvBits = ivBits;
  params->pAAD = aad;
  params->ulAADLen = aadLength;
  params->ulTagBits = tagBits;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_AES_GCM_240_PARAMS);

  return true;
}

/**
 * Reads CK_RSA_PKCS_PSS_PARAMS from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param mechanismParameter The mechanism parameter value.
 * @param mechanism The CK_MECHANISM_PTR structure to store the retrieved parameters.
 * @return true if the parameters were successfully retrieved, false otherwise.
 */
bool get_params_rsa_pss(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(hashAlg, mechanismParameter, CK_RSA_PKCS_PSS_PARAMS);
  READ_ULONG_REQUIRED(mgf, mechanismParameter, CK_RSA_PKCS_PSS_PARAMS);
  READ_ULONG_REQUIRED(saltLen, mechanismParameter, CK_RSA_PKCS_PSS_PARAMS);

  // Create the mechanism parameters structure
  CK_RSA_PKCS_PSS_PARAMS_PTR params = CK_RSA_PKCS_PSS_PARAMS_PTR(malloc(sizeof(CK_RSA_PKCS_PSS_PARAMS)));
  params->hashAlg = hashAlg;
  params->mgf = mgf;
  params->sLen = saltLen;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

  return true;
}

/**
 * Reads CK_ECDH2_DERIVE_PARAMS from a given JavaScript object.
 *
 * @param env The N-API environment.
 * @param mechanismParameter The mechanism parameter value.
 * @param mechanism The CK_MECHANISM_PTR structure to store the retrieved parameters.
 * @return true if the parameters were successfully retrieved, false otherwise.
 */
bool get_params_ecdh2_derive(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(kdf, mechanismParameter, CK_ECDH2_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(sharedData, mechanismParameter, CK_ECDH2_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_ECDH2_DERIVE_PARAMS);
  READ_ULONG_REQUIRED(privateDataLen, mechanismParameter, CK_ECDH2_DERIVE_PARAMS);
  READ_HANDLE_REQUIRED(privateData, mechanismParameter, CK_ECDH2_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(publicData2, mechanismParameter, CK_ECDH2_DERIVE_PARAMS);

  // Create the mechanism parameters structure
  CK_ECDH2_DERIVE_PARAMS_PTR params = CK_ECDH2_DERIVE_PARAMS_PTR(malloc(sizeof(CK_ECDH2_DERIVE_PARAMS)));
  params->kdf = kdf;
  params->pSharedData = sharedData;
  params->ulSharedDataLen = sharedDataLength;
  params->pPublicData = publicData;
  params->ulPublicDataLen = publicDataLength;
  params->ulPrivateDataLen = privateDataLen;
  params->hPrivateData = privateData;
  params->pPublicData2 = publicData2;
  params->ulPublicDataLen2 = publicData2Length;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_ECDH2_DERIVE_PARAMS);

  return true;
}

// Reads CK_ECMQV_DERIVE_PARAMS from a given JavaScript object.
bool get_params_ecmqv_derive(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(kdf, mechanismParameter, CK_ECMQV_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(sharedData, mechanismParameter, CK_ECMQV_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_ECMQV_DERIVE_PARAMS);
  READ_ULONG_REQUIRED(privateDataLen, mechanismParameter, CK_ECMQV_DERIVE_PARAMS);
  READ_HANDLE_REQUIRED(privateData, mechanismParameter, CK_ECMQV_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(publicData2, mechanismParameter, CK_ECMQV_DERIVE_PARAMS);

  // Create the mechanism parameters structure
  CK_ECMQV_DERIVE_PARAMS_PTR params = CK_ECMQV_DERIVE_PARAMS_PTR(malloc(sizeof(CK_ECMQV_DERIVE_PARAMS)));
  params->kdf = kdf;
  params->pSharedData = sharedData;
  params->ulSharedDataLen = sharedDataLength;
  params->pPublicData = publicData;
  params->ulPublicDataLen = publicDataLength;
  params->ulPrivateDataLen = privateDataLen;
  params->hPrivateData = privateData;
  params->pPublicData2 = publicData2;
  params->ulPublicDataLen2 = publicData2Length;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_ECMQV_DERIVE_PARAMS);

  return true;
}

// Reads CK_X9_42_DH1_DERIVE_PARAMS from a given JavaScript object.
bool get_params_x9_42_dh1_derive(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(kdf, mechanismParameter, CK_X9_42_DH1_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(otherInfo, mechanismParameter, CK_X9_42_DH1_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_X9_42_DH1_DERIVE_PARAMS);

  // Create the mechanism parameters structure
  CK_X9_42_DH1_DERIVE_PARAMS_PTR params = CK_X9_42_DH1_DERIVE_PARAMS_PTR(malloc(sizeof(CK_X9_42_DH1_DERIVE_PARAMS)));
  params->kdf = kdf;
  params->pOtherInfo = otherInfo;
  params->ulOtherInfoLen = otherInfoLength;
  params->pPublicData = publicData;
  params->ulPublicDataLen = publicDataLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_X9_42_DH1_DERIVE_PARAMS);

  return true;
}

// Reads CK_X9_42_DH2_DERIVE_PARAMS from a given JavaScript object.
bool get_params_x9_42_dh2_derive(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(kdf, mechanismParameter, CK_X9_42_DH2_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(otherInfo, mechanismParameter, CK_X9_42_DH2_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_X9_42_DH2_DERIVE_PARAMS);
  READ_ULONG_REQUIRED(privateDataLen, mechanismParameter, CK_X9_42_DH2_DERIVE_PARAMS);
  READ_HANDLE_REQUIRED(privateData, mechanismParameter, CK_X9_42_DH2_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(publicData2, mechanismParameter, CK_X9_42_DH2_DERIVE_PARAMS);

  // Create the mechanism parameters structure
  CK_X9_42_DH2_DERIVE_PARAMS_PTR params = CK_X9_42_DH2_DERIVE_PARAMS_PTR(malloc(sizeof(CK_X9_42_DH2_DERIVE_PARAMS)));
  params->kdf = kdf;
  params->pOtherInfo = otherInfo;
  params->ulOtherInfoLen = otherInfoLength;
  params->pPublicData = publicData;
  params->ulPublicDataLen = publicDataLength;
  params->ulPrivateDataLen = privateDataLen;
  params->hPrivateData = privateData;
  params->pPublicData2 = publicData2;
  params->ulPublicDataLen2 = publicData2Length;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_X9_42_DH2_DERIVE_PARAMS);

  return true;
}

// Reads CK_X9_42_MQV_DERIVE_PARAMS from a given JavaScript object.
bool get_params_x9_42_mqv_derive(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(kdf, mechanismParameter, CK_X9_42_MQV_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(otherInfo, mechanismParameter, CK_X9_42_MQV_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_X9_42_MQV_DERIVE_PARAMS);
  READ_ULONG_REQUIRED(privateDataLen, mechanismParameter, CK_X9_42_MQV_DERIVE_PARAMS);
  READ_HANDLE_REQUIRED(privateData, mechanismParameter, CK_X9_42_MQV_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(publicData2, mechanismParameter, CK_X9_42_MQV_DERIVE_PARAMS);
  READ_HANDLE_REQUIRED(publicKey, mechanismParameter, CK_X9_42_MQV_DERIVE_PARAMS);

  // Create the mechanism parameters structure
  CK_X9_42_MQV_DERIVE_PARAMS_PTR params = CK_X9_42_MQV_DERIVE_PARAMS_PTR(malloc(sizeof(CK_X9_42_MQV_DERIVE_PARAMS)));
  params->kdf = kdf;
  params->pOtherInfo = otherInfo;
  params->ulOtherInfoLen = otherInfoLength;
  params->pPublicData = publicData;
  params->ulPublicDataLen = publicDataLength;
  params->ulPrivateDataLen = privateDataLen;
  params->hPrivateData = privateData;
  params->pPublicData2 = publicData2;
  params->ulPublicDataLen2 = publicData2Length;
  params->publicKey = publicKey;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_X9_42_MQV_DERIVE_PARAMS);

  return true;
}

// Reads CK_KEA_DERIVE_PARAMS from a given JavaScript object.
bool get_params_kea_derive(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_BOOL_OPTIONAL(isSender, mechanismParameter, CK_KEA_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(randomA, mechanismParameter, CK_KEA_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(randomB, mechanismParameter, CK_KEA_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_KEA_DERIVE_PARAMS);

  if (randomALength != randomBLength)
  {
    THROW_TYPE_ERRORF(false, "Property 'randomA' and 'randomB' of %s mechanism parameter should be Buffers of equal length", "CK_KEA_DERIVE_PARAMS");
  }

  // Create the mechanism parameters structure
  CK_KEA_DERIVE_PARAMS_PTR params = CK_KEA_DERIVE_PARAMS_PTR(malloc(sizeof(CK_KEA_DERIVE_PARAMS)));
  params->isSender = isSender;
  params->ulRandomLen = randomALength;
  params->pRandomA = randomA;
  params->pRandomB = randomB;
  params->ulPublicDataLen = publicDataLength;
  params->pPublicData = publicData;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_KEA_DERIVE_PARAMS);

  return true;
}

// Reads CK_RC2_CBC_PARAMS from a given JavaScript object.
bool get_params_rc2_cbc(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(effectiveBits, mechanismParameter, CK_RC2_CBC_PARAMS);
  READ_BYTES_REQUIRED(iv, mechanismParameter, CK_RC2_CBC_PARAMS);
  if (ivLength != 8)
  {
    THROW_TYPE_ERRORF(false, "Property 'iv' of %s mechanism parameter should be a Buffer of length 8", "CK_RC2_CBC_PARAMS");
  }

  // Create the mechanism parameters structure
  CK_RC2_CBC_PARAMS_PTR params = CK_RC2_CBC_PARAMS_PTR(malloc(sizeof(CK_RC2_CBC_PARAMS)));
  params->ulEffectiveBits = effectiveBits;
  memcpy(params->iv, iv, 8);

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_RC2_CBC_PARAMS);

  return true;
}

// Reads CK_RC2_MAC_GENERAL_PARAMS from a given JavaScript object.
bool get_params_rc2_mac_general(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(effectiveBits, mechanismParameter, CK_RC2_MAC_GENERAL_PARAMS);
  READ_ULONG_REQUIRED(macLength, mechanismParameter, CK_RC2_MAC_GENERAL_PARAMS);

  // Create the mechanism parameters structure
  CK_RC2_MAC_GENERAL_PARAMS_PTR params = CK_RC2_MAC_GENERAL_PARAMS_PTR(malloc(sizeof(CK_RC2_MAC_GENERAL_PARAMS)));
  params->ulEffectiveBits = effectiveBits;
  params->ulMacLength = macLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_RC2_MAC_GENERAL_PARAMS);

  return true;
}

// Reads CK_RC5_PARAMS from a given JavaScript object.
bool get_params_rc5(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(wordSize, mechanismParameter, CK_RC5_PARAMS);
  READ_ULONG_REQUIRED(rounds, mechanismParameter, CK_RC5_PARAMS);

  // Create the mechanism parameters structure
  CK_RC5_PARAMS_PTR params = CK_RC5_PARAMS_PTR(malloc(sizeof(CK_RC5_PARAMS)));
  params->ulWordsize = wordSize;
  params->ulRounds = rounds;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_RC5_PARAMS);

  return true;
}

// Reads CK_RC5_CBC_PARAMS from a given JavaScript object.
bool get_params_rc5_cbc(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(wordSize, mechanismParameter, CK_RC5_CBC_PARAMS);
  READ_ULONG_REQUIRED(rounds, mechanismParameter, CK_RC5_CBC_PARAMS);
  READ_BYTES_REQUIRED(iv, mechanismParameter, CK_RC5_CBC_PARAMS);

  // Create the mechanism parameters structure
  CK_RC5_CBC_PARAMS_PTR params = CK_RC5_CBC_PARAMS_PTR(malloc(sizeof(CK_RC5_CBC_PARAMS)));
  params->ulWordsize = wordSize;
  params->ulRounds = rounds;
  params->pIv = iv;
  params->ulIvLen = ivLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_RC5_CBC_PARAMS);

  return true;
}

// Reads CK_RC5_MAC_GENERAL_PARAMS from a given JavaScript object.
bool get_params_rc5_mac_general(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_ULONG_REQUIRED(wordSize, mechanismParameter, CK_RC5_MAC_GENERAL_PARAMS);
  READ_ULONG_REQUIRED(rounds, mechanismParameter, CK_RC5_MAC_GENERAL_PARAMS);
  READ_ULONG_REQUIRED(macLength, mechanismParameter, CK_RC5_MAC_GENERAL_PARAMS);

  // Create the mechanism parameters structure
  CK_RC5_MAC_GENERAL_PARAMS_PTR params = CK_RC5_MAC_GENERAL_PARAMS_PTR(malloc(sizeof(CK_RC5_MAC_GENERAL_PARAMS)));
  params->ulWordsize = wordSize;
  params->ulRounds = rounds;
  params->ulMacLength = macLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_RC5_MAC_GENERAL_PARAMS);

  return true;
}

// Reads CK_DES_CBC_ENCRYPT_DATA_PARAMS from a given JavaScript object.
bool get_params_des_cbc_encrypt_data(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_BYTES_REQUIRED(iv, mechanismParameter, CK_DES_CBC_ENCRYPT_DATA_PARAMS);
  if (ivLength != 8)
  {
    THROW_TYPE_ERRORF(false, "Property 'iv' of %s mechanism parameter should be a Buffer of length 8", "CK_DES_CBC_ENCRYPT_DATA_PARAMS");
  }
  READ_BYTES_OPTIONAL(data, mechanismParameter, CK_DES_CBC_ENCRYPT_DATA_PARAMS);

  // Create the mechanism parameters structure
  CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR params = CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR(malloc(sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS)));
  memcpy(params->iv, iv, 8);
  params->pData = data;
  params->length = dataLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS);

  return true;
}

// Reads CK_SKIPJACK_PRIVATE_WRAP_PARAMS from a given JavaScript object.
bool get_params_skipjack_private_wrap(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_BYTES_REQUIRED(password, mechanismParameter, CK_SKIPJACK_PRIVATE_WRAP_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_SKIPJACK_PRIVATE_WRAP_PARAMS);
  READ_BYTES_REQUIRED(primeP, mechanismParameter, CK_SKIPJACK_PRIVATE_WRAP_PARAMS);
  READ_BYTES_REQUIRED(baseG, mechanismParameter, CK_SKIPJACK_PRIVATE_WRAP_PARAMS);
  READ_BYTES_REQUIRED(subprimeQ, mechanismParameter, CK_SKIPJACK_PRIVATE_WRAP_PARAMS);
  READ_BYTES_REQUIRED(randomA, mechanismParameter, CK_SKIPJACK_PRIVATE_WRAP_PARAMS);

  // Create the mechanism parameters structure
  CK_SKIPJACK_PRIVATE_WRAP_PARAMS_PTR params = CK_SKIPJACK_PRIVATE_WRAP_PARAMS_PTR(malloc(sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS)));
  params->ulPasswordLen = passwordLength;
  params->pPassword = password;
  params->ulPublicDataLen = publicDataLength;
  params->pPublicData = publicData;
  params->ulPAndGLen = primePLength + baseGLength;
  params->ulQLen = subprimeQLength;
  params->ulRandomLen = randomALength;
  params->pRandomA = randomA;
  params->pPrimeP = primeP;
  params->pBaseG = baseG;
  params->pSubprimeQ = subprimeQ;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS);

  return true;
}

// Reads CK_SKIPJACK_RELAYX_PARAMS from a given JavaScript object.
bool get_params_skipjack_relayx(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_BYTES_REQUIRED(oldWrappedX, mechanismParameter, CK_SKIPJACK_RELAYX_PARAMS);
  READ_BYTES_REQUIRED(oldPassword, mechanismParameter, CK_SKIPJACK_RELAYX_PARAMS);
  READ_BYTES_REQUIRED(oldPublicData, mechanismParameter, CK_SKIPJACK_RELAYX_PARAMS);
  READ_BYTES_REQUIRED(oldRandomA, mechanismParameter, CK_SKIPJACK_RELAYX_PARAMS);
  READ_BYTES_REQUIRED(newPassword, mechanismParameter, CK_SKIPJACK_RELAYX_PARAMS);
  READ_BYTES_REQUIRED(newPublicData, mechanismParameter, CK_SKIPJACK_RELAYX_PARAMS);
  READ_BYTES_REQUIRED(newRandomA, mechanismParameter, CK_SKIPJACK_RELAYX_PARAMS);

  // Create the mechanism parameters structure
  CK_SKIPJACK_RELAYX_PARAMS_PTR params = CK_SKIPJACK_RELAYX_PARAMS_PTR(malloc(sizeof(CK_SKIPJACK_RELAYX_PARAMS)));
  params->ulOldWrappedXLen = oldWrappedXLength;
  params->pOldWrappedX = oldWrappedX;
  params->ulOldPasswordLen = oldPasswordLength;
  params->pOldPassword = oldPassword;
  params->ulOldPublicDataLen = oldPublicDataLength;
  params->pOldPublicData = oldPublicData;
  params->ulOldRandomLen = oldRandomALength;
  params->pOldRandomA = oldRandomA;
  params->ulNewPasswordLen = newPasswordLength;
  params->pNewPassword = newPassword;
  params->ulNewPublicDataLen = newPublicDataLength;
  params->pNewPublicData = newPublicData;
  params->ulNewRandomLen = newRandomALength;
  params->pNewRandomA = newRandomA;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_SKIPJACK_RELAYX_PARAMS);

  return true;
}

// Reads CK_PBE_PARAMS from a given JavaScript object.
bool get_params_pbe(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  // Read the mechanism parameters
  READ_BYTES_REQUIRED(initVector, mechanismParameter, CK_PBE_PARAMS);
  READ_BYTES_REQUIRED(password, mechanismParameter, CK_PBE_PARAMS);
  READ_BYTES_REQUIRED(salt, mechanismParameter, CK_PBE_PARAMS);
  READ_ULONG_REQUIRED(iteration, mechanismParameter, CK_PBE_PARAMS);

  // Create the mechanism parameters structure
  CK_PBE_PARAMS_PTR params = CK_PBE_PARAMS_PTR(malloc(sizeof(CK_PBE_PARAMS)));
  params->pInitVector = initVector;
  params->pPassword = password;
  params->ulPasswordLen = passwordLength;
  params->pSalt = salt;
  params->ulSaltLen = saltLength;
  params->ulIteration = iteration;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_PBE_PARAMS);

  return true;
}

// Reads CK_KEY_WRAP_SET_OAEP_PARAMS from a given JavaScript object.
bool get_params_key_wrap_set_oaep(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  CK_KEY_WRAP_SET_OAEP_PARAMS_PTR params = CK_KEY_WRAP_SET_OAEP_PARAMS_PTR(malloc(sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS)));

  // Read the mechanism parameters
  READ_BYTE_OPTIONAL(bc, mechanismParameter, CK_KEY_WRAP_SET_OAEP_PARAMS);
  READ_BYTES_OPTIONAL(x, mechanismParameter, CK_KEY_WRAP_SET_OAEP_PARAMS);

  // Create the mechanism parameters structure
  params->bBC = bc;
  params->pX = x;
  params->ulXLen = xLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS);

  return true;
}

// Reads CK_GCM_PARAMS from a given JavaScript object.
bool get_params_gcm(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  CK_GCM_PARAMS_PTR params = CK_GCM_PARAMS_PTR(malloc(sizeof(CK_GCM_PARAMS)));

  // Read the mechanism parameters
  READ_BYTES_REQUIRED(iv, mechanismParameter, CK_GCM_PARAMS);
  READ_ULONG_REQUIRED(ivBits, mechanismParameter, CK_GCM_PARAMS);
  READ_BYTES_OPTIONAL(aad, mechanismParameter, CK_GCM_PARAMS);
  READ_ULONG_OPTIONAL(tagBits, mechanismParameter, CK_GCM_PARAMS);

  // Create the mechanism parameters structure
  params->pIv = iv;
  params->ulIvLen = ivLength;
  params->ulIvBits = ivBits;
  params->pAAD = aad;
  params->ulAADLen = aadLength;
  params->ulTagBits = tagBits;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_GCM_PARAMS);

  return true;
}

// Reads CK_CCM_PARAMS from a given JavaScript object.
bool get_params_ccm(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  CK_CCM_PARAMS_PTR params = CK_CCM_PARAMS_PTR(malloc(sizeof(CK_CCM_PARAMS)));

  // Read the mechanism parameters
  READ_ULONG_REQUIRED(dataLength, mechanismParameter, CK_CCM_PARAMS);
  READ_BYTES_OPTIONAL(nonce, mechanismParameter, CK_CCM_PARAMS);
  READ_BYTES_OPTIONAL(aad, mechanismParameter, CK_CCM_PARAMS);
  READ_ULONG_OPTIONAL(macLength, mechanismParameter, CK_CCM_PARAMS);

  // Create the mechanism parameters structure
  params->ulDataLen = dataLength;
  params->pNonce = nonce;
  params->ulNonceLen = nonceLength;
  params->pAAD = aad;
  params->ulAADLen = aadLength;
  params->ulMACLen = macLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_CCM_PARAMS);

  return true;
}

// Reads CK_GOSTR3410_DERIVE_PARAMS from a given JavaScript object.
bool get_params_gost_r3410_derive(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  CK_GOSTR3410_DERIVE_PARAMS_PTR params = CK_GOSTR3410_DERIVE_PARAMS_PTR(malloc(sizeof(CK_GOSTR3410_DERIVE_PARAMS)));

  // Read the mechanism parameters
  READ_ULONG_REQUIRED(kdf, mechanismParameter, CK_GOSTR3410_DERIVE_PARAMS);
  READ_BYTES_REQUIRED(publicData, mechanismParameter, CK_GOSTR3410_DERIVE_PARAMS);
  READ_BYTES_OPTIONAL(ukm, mechanismParameter, CK_GOSTR3410_DERIVE_PARAMS);

  // Create the mechanism parameters structure
  params->kdf = kdf;
  params->pPublicData = publicData;
  params->ulPublicDataLen = publicDataLength;
  params->pUKM = ukm;
  params->ulUKMLen = ukmLength;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_GOSTR3410_DERIVE_PARAMS);

  return true;
}

// Reads CK_GOSTR3410_KEY_WRAP_PARAMS from a given JavaScript object.
bool get_params_gost_r3410_key_wrap(
    napi_env env,
    napi_value mechanismParameter,
    CK_MECHANISM_PTR mechanism)
{
  CK_GOSTR3410_KEY_WRAP_PARAMS_PTR params = CK_GOSTR3410_KEY_WRAP_PARAMS_PTR(malloc(sizeof(CK_GOSTR3410_KEY_WRAP_PARAMS)));

  // Read the mechanism parameters
  READ_BYTES_REQUIRED(wrapOID, mechanismParameter, CK_GOSTR3410_KEY_WRAP_PARAMS);
  READ_BYTES_OPTIONAL(ukm, mechanismParameter, CK_GOSTR3410_KEY_WRAP_PARAMS);
  READ_HANDLE_REQUIRED(key, mechanismParameter, CK_GOSTR3410_KEY_WRAP_PARAMS);

  // Create the mechanism parameters structure
  params->pWrapOID = wrapOID;
  params->ulWrapOIDLen = wrapOIDLength;
  params->pUKM = ukm;
  params->ulUKMLen = ukmLength;
  params->hKey = key;

  // Set the mechanism parameters
  mechanism->pParameter = params;
  mechanism->ulParameterLen = sizeof(CK_GOSTR3410_KEY_WRAP_PARAMS);

  return true;
}
