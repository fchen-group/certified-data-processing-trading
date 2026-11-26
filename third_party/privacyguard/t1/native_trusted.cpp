// Sanitizer tests only. Exact adapted core + author's Keccak; SGX crypto is
// replaced by an explicitly test-only OpenSSL shim. Not SGX performance data.
#include "native_names.h"
#include "isv_enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_tkey_exchange.h"
#include <cstring>
#include <string>
#include "keccak.h"
sgx_ec_key_128bit_t sk_key_DC,sk_key_DO;
uint8_t g_secret_DC[32];
int num_DOs_here;
sgx_aes_gcm_128bit_key_t* DO_data_key;
uint8_t K_result[16];
std::string K_result_hash,C_result_hash;
#include "t1_core.inc"
