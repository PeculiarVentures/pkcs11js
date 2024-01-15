#include "common.h"

#include "const.cpp"
#include "pkcs11.cpp"

#define DEFINE_PKCS11_METHOD(name)                                               \
  {                                                                              \
    #name, nullptr, Pkcs11::name, nullptr, nullptr, nullptr, attributes, nullptr \
  }

napi_value Init(napi_env env, napi_value exports)
{
  napi_property_attributes attributes = static_cast<napi_property_attributes>(napi_enumerable | napi_writable);
  napi_property_descriptor instance_properties[] = {
      {"load", nullptr, Pkcs11::Load, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"close", nullptr, Pkcs11::Close, nullptr, nullptr, nullptr, napi_default, nullptr},
      DEFINE_PKCS11_METHOD(C_Initialize),
      DEFINE_PKCS11_METHOD(C_Finalize),
      DEFINE_PKCS11_METHOD(C_GetInfo),
      DEFINE_PKCS11_METHOD(C_GetSlotList),
      DEFINE_PKCS11_METHOD(C_GetSlotInfo),
      DEFINE_PKCS11_METHOD(C_GetTokenInfo),
      DEFINE_PKCS11_METHOD(C_GetMechanismList),
      DEFINE_PKCS11_METHOD(C_GetMechanismInfo),
      DEFINE_PKCS11_METHOD(C_InitToken),
      DEFINE_PKCS11_METHOD(C_InitPIN),
      DEFINE_PKCS11_METHOD(C_SetPIN),
      DEFINE_PKCS11_METHOD(C_OpenSession),
      DEFINE_PKCS11_METHOD(C_CloseSession),
      DEFINE_PKCS11_METHOD(C_CloseAllSessions),
      DEFINE_PKCS11_METHOD(C_GetSessionInfo),
      DEFINE_PKCS11_METHOD(C_GetOperationState),
      DEFINE_PKCS11_METHOD(C_SetOperationState),
      DEFINE_PKCS11_METHOD(C_Login),
      DEFINE_PKCS11_METHOD(C_Logout),
      DEFINE_PKCS11_METHOD(C_SeedRandom),
      DEFINE_PKCS11_METHOD(C_GenerateRandom),
      DEFINE_PKCS11_METHOD(C_CreateObject),
      DEFINE_PKCS11_METHOD(C_CopyObject),
      DEFINE_PKCS11_METHOD(C_DestroyObject),
      DEFINE_PKCS11_METHOD(C_GetObjectSize),
      DEFINE_PKCS11_METHOD(C_GetAttributeValue),
      DEFINE_PKCS11_METHOD(C_SetAttributeValue),
      DEFINE_PKCS11_METHOD(C_FindObjectsInit),
      DEFINE_PKCS11_METHOD(C_FindObjects),
      DEFINE_PKCS11_METHOD(C_FindObjectsFinal),
      DEFINE_PKCS11_METHOD(C_DigestInit),
      DEFINE_PKCS11_METHOD(C_Digest),
      DEFINE_PKCS11_METHOD(C_DigestCallback),
      DEFINE_PKCS11_METHOD(C_DigestUpdate),
      DEFINE_PKCS11_METHOD(C_DigestKey),
      DEFINE_PKCS11_METHOD(C_DigestFinal),
      DEFINE_PKCS11_METHOD(C_DigestFinalCallback),
      DEFINE_PKCS11_METHOD(C_GenerateKey),
      DEFINE_PKCS11_METHOD(C_GenerateKeyCallback),
      DEFINE_PKCS11_METHOD(C_GenerateKeyPair),
      DEFINE_PKCS11_METHOD(C_GenerateKeyPairCallback),
      DEFINE_PKCS11_METHOD(C_SignInit),
      DEFINE_PKCS11_METHOD(C_Sign),
      DEFINE_PKCS11_METHOD(C_SignCallback),
      DEFINE_PKCS11_METHOD(C_SignUpdate),
      DEFINE_PKCS11_METHOD(C_SignFinal),
      DEFINE_PKCS11_METHOD(C_SignFinalCallback),
      DEFINE_PKCS11_METHOD(C_VerifyInit),
      DEFINE_PKCS11_METHOD(C_Verify),
      DEFINE_PKCS11_METHOD(C_VerifyCallback),
      DEFINE_PKCS11_METHOD(C_VerifyUpdate),
      DEFINE_PKCS11_METHOD(C_VerifyFinal),
      DEFINE_PKCS11_METHOD(C_VerifyFinalCallback),
      DEFINE_PKCS11_METHOD(C_EncryptInit),
      DEFINE_PKCS11_METHOD(C_Encrypt),
      DEFINE_PKCS11_METHOD(C_EncryptCallback),
      DEFINE_PKCS11_METHOD(C_EncryptUpdate),
      DEFINE_PKCS11_METHOD(C_EncryptFinal),
      DEFINE_PKCS11_METHOD(C_EncryptFinalCallback),
      DEFINE_PKCS11_METHOD(C_DecryptInit),
      DEFINE_PKCS11_METHOD(C_Decrypt),
      DEFINE_PKCS11_METHOD(C_DecryptCallback),
      DEFINE_PKCS11_METHOD(C_DecryptUpdate),
      DEFINE_PKCS11_METHOD(C_DecryptFinal),
      DEFINE_PKCS11_METHOD(C_DecryptFinalCallback),
      DEFINE_PKCS11_METHOD(C_DeriveKey),
      DEFINE_PKCS11_METHOD(C_DeriveKeyCallback),
      DEFINE_PKCS11_METHOD(C_WrapKey),
      DEFINE_PKCS11_METHOD(C_WrapKeyCallback),
      DEFINE_PKCS11_METHOD(C_UnwrapKey),
      DEFINE_PKCS11_METHOD(C_UnwrapKeyCallback),
      DEFINE_PKCS11_METHOD(C_SignRecoverInit),
      DEFINE_PKCS11_METHOD(C_SignRecover),
      DEFINE_PKCS11_METHOD(C_VerifyRecoverInit),
      DEFINE_PKCS11_METHOD(C_VerifyRecover),
      DEFINE_PKCS11_METHOD(C_WaitForSlotEvent),
      DEFINE_PKCS11_METHOD(C_DigestEncryptUpdate),
      DEFINE_PKCS11_METHOD(C_DigestEncryptUpdateCallback),
      DEFINE_PKCS11_METHOD(C_DecryptDigestUpdate),
      DEFINE_PKCS11_METHOD(C_DecryptDigestUpdateCallback),
      DEFINE_PKCS11_METHOD(C_SignEncryptUpdate),
      DEFINE_PKCS11_METHOD(C_SignEncryptUpdateCallback),
      DEFINE_PKCS11_METHOD(C_DecryptVerifyUpdate),
      DEFINE_PKCS11_METHOD(C_DecryptVerifyUpdateCallback),
  };
  napi_value constructor;
  napi_define_class(env, "PKCS11", NAPI_AUTO_LENGTH, Pkcs11::Constructor, nullptr, sizeof(instance_properties) / sizeof(*instance_properties), instance_properties, &constructor);
  napi_create_reference(env, constructor, 1, &constructorRef);
  napi_set_named_property(env, exports, "PKCS11", constructor);

  set_all_const(env, exports);

  return exports;
}

#undef DEFINE_PKCS11_METHOD

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)