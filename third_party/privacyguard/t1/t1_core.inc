// Included in the formal CEE source; benchmark and production use these same
// ECALLs. Test session injection is compiled ONLY with PG_BENCHMARK.
#include "adult_t1.hpp"
#include <atomic>
#include <new>
#include <memory>

namespace {
std::atomic_flag pg_busy = ATOMIC_FLAG_INIT;
struct PgLock {
    bool held;
    PgLock():held(!pg_busy.test_and_set(std::memory_order_acquire)) {}
    ~PgLock(){ if(held) pg_busy.clear(std::memory_order_release); }
};
bool pg_configured=false,pg_do_ready=false,pg_dc_ready=false;
bool pg_computed=false,pg_delivered=false,pg_failed=false;
#ifdef PG_BENCHMARK
bool pg_test_sessions=false;
sgx_ec_key_128bit_t pg_test_do,pg_test_dc;
#endif
void pg_wipe(void* p,size_t n) { volatile uint8_t* q=static_cast<volatile uint8_t*>(p); while(n--) *q++=0; }
struct PgBuffer {
    uint8_t* p; size_t n;
    explicit PgBuffer(size_t size):p(static_cast<uint8_t*>(malloc(size))),n(size) {}
    ~PgBuffer(){if(p){pg_wipe(p,n);free(p);}}
};
sgx_status_t pg_fail(sgx_status_t status) {
    pg_failed=true;pg_computed=false;
    pg_wipe(K_result,sizeof(K_result));
    pg_wipe(sk_key_DO,16);pg_wipe(sk_key_DC,16);pg_wipe(g_secret_DC,32);
    if(DO_data_key){pg_wipe(DO_data_key[0],16);free(DO_data_key);DO_data_key=NULL;}
#ifdef PG_BENCHMARK
    pg_wipe(pg_test_do,16);pg_wipe(pg_test_dc,16);
#endif
    if(!K_result_hash.empty()) pg_wipe(&K_result_hash[0],K_result_hash.size());
    if(!C_result_hash.empty()) pg_wipe(&C_result_hash[0],C_result_hash.size());
    K_result_hash.clear();C_result_hash.clear();
    return status;
}
void pg_nonce(uint8_t out[12],uint8_t number) { memset(out,0,12);out[11]=number; }
std::string pg_hash_hex(const uint8_t* p,size_t n) {
    const char* digits="0123456789abcdef";
    std::string encoded(n*2,'\0');
    for(size_t i=0;i<n;++i){encoded[2*i]=digits[p[i]>>4];encoded[2*i+1]=digits[p[i]&15];}
    Keccak hash;
    std::string digest=hash(encoded.data(),encoded.size());
    pg_wipe(&encoded[0],encoded.size());
    return digest;
}
bool pg_digest_bytes(const std::string& s,uint8_t out[32]) {
    if(s.size()!=64) return false;
    for(size_t i=0;i<32;++i){
        unsigned v=0;
        for(size_t j=0;j<2;++j){char c=s[2*i+j];if(c>='0'&&c<='9')v=v*16+c-'0';else if(c>='a'&&c<='f')v=v*16+c-'a'+10;else return false;}
        out[i]=uint8_t(v);
    }
    return true;
}
sgx_status_t pg_session_key(sgx_ra_context_t context,uint32_t role,sgx_ec_key_128bit_t* out) {
#ifdef PG_BENCHMARK
    if(pg_test_sessions) { memcpy(out,role==1?pg_test_dc:pg_test_do,16);return SGX_SUCCESS; }
#endif
    return sgx_ra_get_keys(context,SGX_RA_KEY_SK,out);
}
}

sgx_status_t ECALL_enclave_DO_config(int num_DOs) {
    PgLock lock; if(!lock.held) return SGX_ERROR_BUSY;
    // The selected comparison configuration has one DO and one input file.
    if(pg_configured||pg_failed||num_DOs!=1) return pg_fail(SGX_ERROR_INVALID_PARAMETER);
    DO_data_key=static_cast<sgx_aes_gcm_128bit_key_t*>(calloc(1,sizeof(sgx_aes_gcm_128bit_key_t)));
    if(!DO_data_key) return pg_fail(SGX_ERROR_OUT_OF_MEMORY);
    num_DOs_here=1;pg_configured=true;
    return SGX_SUCCESS;
}

#ifdef PG_BENCHMARK
sgx_status_t ECALL_prepare_test_sessions(uint8_t* ida,uint8_t* dc) {
    PgLock lock; if(!lock.held) return SGX_ERROR_BUSY;
    if(!pg_configured||pg_failed||pg_test_sessions||pg_do_ready||pg_dc_ready||!ida||!dc||memcmp(ida,dc,16)==0)
        return pg_fail(SGX_ERROR_INVALID_PARAMETER);
    memcpy(pg_test_do,ida,16);memcpy(pg_test_dc,dc,16);pg_test_sessions=true;
    return SGX_SUCCESS;
}
#endif

sgx_status_t ECALL_put_secret_data(sgx_ra_context_t context,uint8_t* encrypted,
    uint32_t size,uint8_t* tag,uint32_t role) {
    PgLock lock;if(!lock.held)return SGX_ERROR_BUSY;
    if(!pg_configured||pg_failed||pg_computed||!encrypted||!tag||
       (role!=1&&role!=2)||size!=(role==1?32U:16U)||
       (role==1?pg_dc_ready:pg_do_ready)) return pg_fail(SGX_ERROR_INVALID_PARAMETER);
    sgx_ec_key_128bit_t key={0};uint8_t plaintext[32]={0},nonce[12]={0};
    sgx_status_t status=pg_session_key(context,role,&key);
    if(status==SGX_SUCCESS) status=sgx_rijndael128GCM_decrypt(&key,encrypted,size,plaintext,nonce,12,NULL,0,
        reinterpret_cast<const sgx_aes_gcm_128bit_tag_t*>(tag));
    if(status==SGX_SUCCESS) {
        if(role==1) {memcpy(sk_key_DC,key,16);memcpy(g_secret_DC,plaintext,32);pg_dc_ready=true;}
        else {memcpy(sk_key_DO,key,16);memcpy(DO_data_key[0],plaintext,16);pg_do_ready=true;}
        if(pg_dc_ready&&pg_do_ready&&memcmp(sk_key_DC,sk_key_DO,16)==0) status=SGX_ERROR_INVALID_PARAMETER;
    }
    pg_wipe(key,16);pg_wipe(plaintext,sizeof(plaintext));
    return status==SGX_SUCCESS?status:pg_fail(status);
}

sgx_status_t ECALL_compute_task1(sgx_ra_context_t context,uint32_t data_num,
    uint32_t* sizes,uint32_t* mac_sizes,uint8_t* encrypted,uint32_t size,
    uint8_t* tag,uint32_t tag_size,uint8_t* output,uint32_t capacity,
    uint8_t* output_tag,uint32_t* output_length) {
    (void)context;
    PgLock lock;if(!lock.held)return SGX_ERROR_BUSY;
    if(output_length)*output_length=0;
    if(output&&capacity<=PG_RESULT_CAP)memset(output,0,capacity);
    if(output_tag)memset(output_tag,0,16);
    if(!pg_configured||!pg_do_ready||!pg_dc_ready||pg_failed||pg_computed||pg_delivered||
       data_num!=1||!sizes||!mac_sizes||!encrypted||!tag||!output||!output_tag||!output_length||
       !size||size>PG_MAX_INPUT||sizes[0]!=size||tag_size!=16||mac_sizes[0]!=16||capacity!=PG_RESULT_CAP)
        return pg_fail(SGX_ERROR_INVALID_PARAMETER);
    try {
        PgBuffer plain(size);
        if(!plain.p) return pg_fail(SGX_ERROR_OUT_OF_MEMORY);
        uint8_t nonce[12]={0};
        sgx_status_t status=sgx_rijndael128GCM_decrypt(&DO_data_key[0],encrypted,size,plain.p,nonce,12,NULL,0,
            reinterpret_cast<const sgx_aes_gcm_128bit_tag_t*>(tag));
        if(status!=SGX_SUCCESS)return pg_fail(status);
        std::string result;
        if(!pg_adult_statistics(plain.p,size,result))return pg_fail(SGX_ERROR_INVALID_PARAMETER);
        status=sgx_read_rand(K_result,sizeof(K_result));
        if(status==SGX_SUCCESS)status=sgx_rijndael128GCM_encrypt(
            reinterpret_cast<const sgx_aes_gcm_128bit_key_t*>(K_result),
            reinterpret_cast<const uint8_t*>(result.data()),uint32_t(result.size()),output,nonce,12,NULL,0,
            reinterpret_cast<sgx_aes_gcm_128bit_tag_t*>(output_tag));
        size_t length=result.size();pg_wipe(&result[0],result.size());
        if(status!=SGX_SUCCESS){memset(output,0,capacity);memset(output_tag,0,16);return pg_fail(status);}
        // Keep the author's Keccak-256 over lowercase hexadecimal, with exact lengths.
        K_result_hash=pg_hash_hex(K_result,sizeof(K_result));
        C_result_hash=pg_hash_hex(output,length);
        *output_length=uint32_t(length);pg_computed=true;
        pg_wipe(DO_data_key[0],16);free(DO_data_key);DO_data_key=NULL;
        return SGX_SUCCESS;
    } catch(const std::bad_alloc&) {
        memset(output,0,capacity);memset(output_tag,0,16);return pg_fail(SGX_ERROR_OUT_OF_MEMORY);
    } catch(...) {
        memset(output,0,capacity);memset(output_tag,0,16);return pg_fail(SGX_ERROR_UNEXPECTED);
    }
}

sgx_status_t ECALL_get_K_result_hashes(sgx_ra_context_t context,uint8_t* key_en,uint8_t* key_tag,
    uint8_t* kh_en,uint8_t* kh_tag,uint8_t* ch_en,uint8_t* ch_tag,
    uint8_t* key_nonce,uint8_t* kh_nonce,uint8_t* ch_nonce) {
    (void)context;
    PgLock lock;if(!lock.held)return SGX_ERROR_BUSY;
    if(!key_en||!key_tag||!kh_en||!kh_tag||!ch_en||!ch_tag||!key_nonce||!kh_nonce||!ch_nonce)
        return pg_fail(SGX_ERROR_INVALID_PARAMETER);
    auto clear_outputs=[&](){memset(key_en,0,16);memset(key_tag,0,16);memset(kh_en,0,32);memset(kh_tag,0,16);
        memset(ch_en,0,32);memset(ch_tag,0,16);memset(key_nonce,0,12);memset(kh_nonce,0,12);memset(ch_nonce,0,12);};
    clear_outputs();
    if(pg_failed||!pg_computed||pg_delivered)return pg_fail(SGX_ERROR_INVALID_STATE);
    uint8_t kh[32]={0},ch[32]={0};
    if(!pg_digest_bytes(K_result_hash,kh)||!pg_digest_bytes(C_result_hash,ch))return pg_fail(SGX_ERROR_UNEXPECTED);
    // Per session/role: provision nonce 0; iDA key delivery 1; DC hash deliveries 1,2.
    pg_nonce(key_nonce,1);pg_nonce(kh_nonce,1);pg_nonce(ch_nonce,2);
    sgx_status_t status=sgx_rijndael128GCM_encrypt(&sk_key_DO,K_result,16,key_en,key_nonce,12,NULL,0,
        reinterpret_cast<sgx_aes_gcm_128bit_tag_t*>(key_tag));
    if(status==SGX_SUCCESS)status=sgx_rijndael128GCM_encrypt(&sk_key_DC,kh,32,kh_en,kh_nonce,12,NULL,0,
        reinterpret_cast<sgx_aes_gcm_128bit_tag_t*>(kh_tag));
    if(status==SGX_SUCCESS)status=sgx_rijndael128GCM_encrypt(&sk_key_DC,ch,32,ch_en,ch_nonce,12,NULL,0,
        reinterpret_cast<sgx_aes_gcm_128bit_tag_t*>(ch_tag));
#ifdef PG_BENCHMARK
    // Last protected material is ready. Record the endpoint before post-delivery wiping/ECALL return.
    if(status==SGX_SUCCESS)status=OCALL_processing_end();
#endif
    pg_wipe(kh,32);pg_wipe(ch,32);
    if(status!=SGX_SUCCESS){clear_outputs();return pg_fail(status);}
    pg_delivered=true;
    pg_wipe(K_result,16);pg_wipe(sk_key_DO,16);pg_wipe(sk_key_DC,16);
    pg_wipe(g_secret_DC,32);
#ifdef PG_BENCHMARK
    pg_wipe(pg_test_do,16);pg_wipe(pg_test_dc,16);
#endif
    pg_wipe(&K_result_hash[0],K_result_hash.size());pg_wipe(&C_result_hash[0],C_result_hash.size());
    K_result_hash.clear();C_result_hash.clear();
    return SGX_SUCCESS;
}
