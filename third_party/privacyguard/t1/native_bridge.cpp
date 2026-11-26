#include "native_names.h"
#include "isv_enclave_t.h"
#undef ECALL_prepare_test_sessions
#undef ECALL_enclave_DO_config
#undef ECALL_put_secret_data
#undef ECALL_compute_task1
#undef ECALL_get_K_result_hashes
#undef OCALL_processing_end
#undef OCALL_print_string
#include "sgx_urts.h"
extern "C" void OCALL_processing_end();
extern "C" sgx_status_t pg_native_end(){OCALL_processing_end();return SGX_SUCCESS;}
extern "C" sgx_status_t ECALL_prepare_test_sessions(sgx_enclave_id_t,sgx_status_t* r,uint8_t* a,uint8_t* b){*r=pg_trusted_prepare(a,b);return SGX_SUCCESS;}
extern "C" sgx_status_t ECALL_enclave_DO_config(sgx_enclave_id_t,sgx_status_t* r,int n){*r=pg_trusted_config(n);return SGX_SUCCESS;}
extern "C" sgx_status_t ECALL_put_secret_data(sgx_enclave_id_t,sgx_status_t* r,sgx_ra_context_t c,uint8_t* e,uint32_t n,uint8_t* t,uint32_t role){*r=pg_trusted_provision(c,e,n,t,role);return SGX_SUCCESS;}
extern "C" sgx_status_t ECALL_compute_task1(sgx_enclave_id_t,sgx_status_t* r,sgx_ra_context_t c,uint32_t dn,uint32_t* sizes,uint32_t* ms,uint8_t* e,uint32_t n,uint8_t* t,uint32_t tn,uint8_t* out,uint32_t cap,uint8_t* ot,uint32_t* len){*r=pg_trusted_compute(c,dn,sizes,ms,e,n,t,tn,out,cap,ot,len);return SGX_SUCCESS;}
extern "C" sgx_status_t ECALL_get_K_result_hashes(sgx_enclave_id_t,sgx_status_t* r,sgx_ra_context_t c,uint8_t* a,uint8_t* b,uint8_t* d,uint8_t* e,uint8_t* f,uint8_t* g,uint8_t* h,uint8_t* i,uint8_t* j){*r=pg_trusted_deliver(c,a,b,d,e,f,g,h,i,j);return SGX_SUCCESS;}
