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
bool ge_params_rsa_pss(
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
