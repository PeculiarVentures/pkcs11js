#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <vector>
#include <node_api.h>
#include <cstdarg>
#include <string>

#ifdef _WIN32
// Use Windows-specific definitions
#pragma pack(push, cryptoki, 1)
#endif
#include <pkcs11/pkcs11.h>

// Extended structure for NSS
typedef struct CK_NSS_C_INITIALIZE_ARGS
{
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_CHAR_PTR LibraryParameters;
  CK_VOID_PTR pReserved;
} CK_NSS_C_INITIALIZE_ARGS;

typedef CK_NSS_C_INITIALIZE_ARGS *CK_NSS_C_INITIALIZE_ARGS_PTR;

#ifdef _WIN32
// Restore default packing
#pragma pack(pop, cryptoki)
#endif

#ifndef _WIN32
#include <dlfcn.h>
#else
#include "dl.h"
#endif

typedef CK_GCM_PARAMS CK_AES_GCM_240_PARAMS;
typedef CK_AES_GCM_240_PARAMS CK_PTR CK_AES_GCM_240_PARAMS_PTR;

// Types of parameters
#define CK_PARAMS_BUFFER 0
#define CK_PARAMS_AES_CBC 1
#define CK_PARAMS_AES_CCM 2
#define CK_PARAMS_AES_GCM 3
#define CK_PARAMS_RSA_OAEP 4
#define CK_PARAMS_RSA_PSS 5
#define CK_PARAMS_EC_DH 6
#define CK_PARAMS_AES_GCM_v240 7
#define CK_PARAMS_ECDH2_DERIVE 8
#define CK_PARAMS_ECMQV_DERIVE 9
#define CK_PARAMS_X9_42_DH1_DERIVE 10
#define CK_PARAMS_X9_42_DH2_DERIVE 11
#define CK_PARAMS_X9_42_MQV_DERIVE 12
#define CK_PARAMS_KEA_DERIVE 13
#define CK_PARAMS_RC2 14
#define CK_PARAMS_RC2_CBC 15
#define CK_PARAMS_RC2_MAC_GENERAL 16
#define CK_PARAMS_RC5 17
#define CK_PARAMS_RC5_CBC 18
#define CK_PARAMS_RC5_MAC_GENERAL 19
#define CK_PARAMS_DES_CBC_ENCRYPT_DATA 20
#define CK_PARAMS_SKIPJACK_PRIVATE_WRAP 21
#define CK_PARAMS_SKIPJACK_RELAYX 22
#define CK_PARAMS_PBE 23
#define CK_PARAMS_KEY_WRAP_SET_OAEP 24
#define CK_PARAMS_GCM 25
#define CK_PARAMS_CCM 26
#define CK_PARAM_GOSTR3410_DERIVE 27
#define CK_PARAM_GOSTR3410_KEY_WRAP 28

/**
 * @brief Retrieves the name of the error code.
 *
 * This function takes a CK_RV error code as input and returns the corresponding
 * name of the error. The error name is a string representation of the error code.
 *
 * @param rv The CK_RV error code.
 * @return The name of the error code as a const char pointer.
 */
const char *get_error_name(CK_RV rv);

/**
 * @brief Throws an error based on the CK_RV error code.
 *
 * This function takes a CK_RV error code as input and throws an error based on
 * the error code. The error message is a string representation of the error name
 * and the error code separated by a colon (e.g. "CKR_ARGUMENTS_BAD:5").
 *
 * @param env The n-api environment.
 * @param rv The CK_RV error code.
 */
void throw_rv_error(napi_env env, CK_RV rv);
/**
 * @brief Throws a type error with a formatted message.
 *
 * @param env The N-API environment.
 * @param format The format string for the error message.
 * @param ... The arguments to be formatted into the error message.
 */
void throw_type_errorf(napi_env env, const char *format, ...);

/**
 * @brief Macro for throwing a type error with a formatted message and returning a value.
 *
 * @param returnValue The value to be returned.
 * @param format The format string for the error message.
 * @param ... The arguments to be formatted into the error message.
 */
#define THROW_TYPE_ERRORF(returnValue, format, ...) \
  throw_type_errorf(env, format, __VA_ARGS__);      \
  return returnValue;
/**
 * Checks if the given value is an Object.
 *
 * @param env The N-API environment.
 * @param value The value to be checked.
 * @return True if the value is an object, false otherwise.
 */
bool is_object(napi_env env, napi_value value);
/**
 * Checks if the given value is a String.
 *
 * @param env The N-API environment.
 * @param value The value to be checked.
 * @return True if the value is a string, false otherwise.
 */
bool is_string(napi_env env, napi_value value);
/**
 * Checks if the given value is a Number.
 *
 * @param env The N-API environment.
 * @param value The value to be checked.
 * @return True if the value is a number, false otherwise.
 */
bool is_number(napi_env env, napi_value value);
/**
 * Checks if the given value is an Array.
 *
 * @param env The N-API environment.
 * @param value The value to be checked.
 * @return True if the value is an array, false otherwise.
 */
bool is_array(napi_env env, napi_value value);
/**
 * Checks if the given value is a Buffer.
 *
 * @param env The N-API environment.
 * @param value The value to be checked.
 * @return True if the value is a buffer, false otherwise.
 */
bool is_buffer(napi_env env, napi_value value);
/**
 * Checks if the given value is an empty value (Null or Undefined)
 *
 * @param env The N-API environment.
 * @param value The value to be checked.
 * @return True if the value is a boolean, false otherwise.
 */
bool is_empty(napi_env env, napi_value value);
/**
 * Checks if the given value is a Function.
 *
 * @param env The N-API environment.
 * @param value The value to be checked.
 * @return True if the value is a function, false otherwise.
 */
bool is_function(napi_env env, napi_value value);

/**
 * @brief A wrapper class for CK_MECHANISM structure.
 *
 * This class provides a convenient way to manage CK_MECHANISM objects by automatically disposing them when they are no longer needed.
 */
class MechanismWrapper
{
public:
  CK_MECHANISM *value; // Pointer to the CK_MECHANISM object.
  bool dispose;        // Flag indicating whether the CK_MECHANISM object should be disposed.

  /**
   * @brief Constructs a MechanismWrapper object with the specified CK_MECHANISM object and disposal flag.
   *
   * @param mechanism Pointer to the CK_MECHANISM object.
   * @param dispose Flag indicating whether the CK_MECHANISM object should be disposed. Default is false.
   */
  MechanismWrapper(CK_MECHANISM *mechanism, bool dispose = false);

  /**
   * @brief Default constructor for MechanismWrapper.
   *
   * Initializes the CK_MECHANISM object to NULL and sets the dispose flag to true.
   */
  MechanismWrapper();

  /**
   * @brief Destructor for MechanismWrapper.
   *
   * Automatically disposes the CK_MECHANISM object and its members if the dispose flag is set to true.
   */
  ~MechanismWrapper();
};

/**
 * @brief A class that wraps CK_ATTRIBUTE_PTR and provides utility functions for managing attributes.
 */
class AttributesWrapper
{
public:
  CK_ATTRIBUTE_PTR attributes; // Pointer to the CK_ATTRIBUTE array.
  CK_ULONG length;             // The length of the attributes array.
  bool dispose;                // Flag indicating whether the attributes should be disposed.

  /**
   * @brief Constructs an AttributesWrapper object with the given attributes and length.
   * @param attributes The pointer to the CK_ATTRIBUTE array.
   * @param length The length of the attributes array.
   * @param dispose Flag indicating whether the attributes should be disposed.
   */
  AttributesWrapper(CK_ATTRIBUTE_PTR attributes, CK_ULONG length, bool dispose = false);

  /**
   * @brief Constructs an AttributesWrapper object with the given length.
   * @param length The length of the attributes array.
   */
  AttributesWrapper(CK_ULONG length);

  /**
   * @brief Destructor for the AttributesWrapper object. Automatically disposes the attributes
   * if the dispose flag is set to true.
   */
  ~AttributesWrapper();

  /**
   * @brief Allocates memory for the value of the attribute at the specified index.
   * @param index The index of the attribute.
   * @param length The length of the value to be allocated.
   */
  void allocValue(CK_ULONG index, CK_ULONG length);

  /**
   * @brief Allocates memory for the values of all attributes.
   */
  void allocAllValues();
};

#endif // COMMON_H