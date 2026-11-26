// Functional-test replacement, not part of either SDK/HW enclave.
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tkey_exchange.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <climits>
#include <cstdlib>
static unsigned calls=0;
static bool injected(){const char* at=getenv("PG_FAIL_CRYPTO_AT");return ++calls==unsigned(at?strtoul(at,nullptr,10):0);}
extern "C" sgx_status_t sgx_read_rand(unsigned char* p,size_t n){if(injected())return SGX_ERROR_UNEXPECTED;return n<=INT_MAX&&RAND_bytes(p,int(n))==1?SGX_SUCCESS:SGX_ERROR_UNEXPECTED;}
extern "C" sgx_status_t sgx_ra_get_keys(sgx_ra_context_t,sgx_ra_key_type_t,sgx_ra_key_128_t*){return SGX_ERROR_INVALID_STATE;}
extern "C" sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t* k,const uint8_t* src,uint32_t n,uint8_t* dest,const uint8_t* iv,uint32_t ivn,const uint8_t* aad,uint32_t an,sgx_aes_gcm_128bit_tag_t* tag){
 if(injected())return SGX_ERROR_UNEXPECTED;
 if(n>INT_MAX||an>INT_MAX||ivn!=12)return SGX_ERROR_INVALID_PARAMETER;
 EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();if(!ctx)return SGX_ERROR_OUT_OF_MEMORY;int len=0,last=0,unused=0;
 bool ok=EVP_EncryptInit_ex(ctx,EVP_aes_128_gcm(),nullptr,*k,iv)==1;
 if(ok&&an)ok=EVP_EncryptUpdate(ctx,nullptr,&unused,aad,int(an))==1;
 ok=ok&&EVP_EncryptUpdate(ctx,dest,&len,src,int(n))==1&&EVP_EncryptFinal_ex(ctx,dest+len,&last)==1&&EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,*tag)==1;
 EVP_CIPHER_CTX_free(ctx);return ok&&len+last==int(n)?SGX_SUCCESS:SGX_ERROR_UNEXPECTED;
}
extern "C" sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t* k,const uint8_t* src,uint32_t n,uint8_t* dest,const uint8_t* iv,uint32_t ivn,const uint8_t* aad,uint32_t an,const sgx_aes_gcm_128bit_tag_t* tag){
 if(injected())return SGX_ERROR_UNEXPECTED;
 if(n>INT_MAX||an>INT_MAX||ivn!=12)return SGX_ERROR_INVALID_PARAMETER;
 EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();if(!ctx)return SGX_ERROR_OUT_OF_MEMORY;int len=0,last=0,unused=0;
 bool ok=EVP_DecryptInit_ex(ctx,EVP_aes_128_gcm(),nullptr,*k,iv)==1;
 if(ok&&an)ok=EVP_DecryptUpdate(ctx,nullptr,&unused,aad,int(an))==1;
 ok=ok&&EVP_DecryptUpdate(ctx,dest,&len,src,int(n))==1&&EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,const_cast<uint8_t*>(*tag))==1&&EVP_DecryptFinal_ex(ctx,dest+len,&last)==1;
 EVP_CIPHER_CTX_free(ctx);return ok&&len+last==int(n)?SGX_SUCCESS:SGX_ERROR_MAC_MISMATCH;
}
