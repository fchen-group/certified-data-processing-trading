#include "t1_io.h"
#include <cstdio>
#include <cstring>
#include <new>
#include <cerrno>
#include <sys/stat.h>
static const uint32_t PG_INPUT_LIMIT=32U*1024U*1024U;
bool pg_read_exact(const char* path,size_t max,std::vector<uint8_t>& bytes) {
    bytes.clear();
    FILE* f=fopen(path,"rb");if(!f)return false;
    struct stat st;
    if(fstat(fileno(f),&st)!=0||!S_ISREG(st.st_mode)||st.st_size<=0||uint64_t(st.st_size)>max){fclose(f);return false;}
    try{bytes.resize(size_t(st.st_size));}catch(const std::bad_alloc&){fclose(f);return false;}
    size_t got=fread(bytes.data(),1,bytes.size(),f);
    bool ok=got==bytes.size()&&!ferror(f)&&fgetc(f)==EOF&&!ferror(f);
    if(fclose(f)!=0)ok=false;
    if(!ok)bytes.clear();
    return ok;
}
bool pg_write_exact(const char* path,const uint8_t* data,size_t size) {
    FILE* f=fopen(path,"wbx");if(!f)return false;
    bool ok=fwrite(data,1,size,f)==size;
    if(fclose(f)!=0)ok=false;
    if(!ok)remove(path);
    return ok;
}
int pg_read_compute(enclave_info_t* enclave,const char* ciphertext,const char* tag_path,PgOutput& out) {
    out=PgOutput{};
    std::vector<uint8_t> data,tag;
    if(!enclave||!pg_read_exact(ciphertext,PG_INPUT_LIMIT,data)||!pg_read_exact(tag_path,16,tag)||tag.size()!=16)return 1;
    uint32_t size=uint32_t(data.size()),mac_size=16,actual=0;
    try{out.ciphertext.resize(TASK1_RESULT_SIZE);}catch(const std::bad_alloc&){return 1;}
    sgx_status_t status=SGX_ERROR_UNEXPECTED;
    sgx_status_t outer=ECALL_compute_task1(enclave->enclave_id,&status,enclave->context,1,&size,&mac_size,
        data.data(),size,tag.data(),mac_size,out.ciphertext.data(),TASK1_RESULT_SIZE,out.tag.data(),&actual);
    if(outer!=SGX_SUCCESS||status!=SGX_SUCCESS||actual==0||actual>TASK1_RESULT_SIZE){out=PgOutput{};return 1;}
    out.ciphertext.resize(actual);
    return 0;
}
int pg_make_delivery(enclave_info_t* enclave,K_result_msg_t& ida,K_result_hash_msg_t& dc) {
    memset(&ida,0,sizeof(ida));memset(&dc,0,sizeof(dc));
    if(!enclave)return 1;
    sgx_status_t status=SGX_ERROR_UNEXPECTED;
    sgx_status_t outer=ECALL_get_K_result_hashes(enclave->enclave_id,&status,enclave->context,
        ida.K_result_en,ida.K_result_mac,dc.K_result_hash_en,dc.K_result_hash_mac,
        dc.C_result_hash_en,dc.C_result_hash_mac,ida.K_result_nonce,dc.K_result_hash_nonce,dc.C_result_hash_nonce);
    if(outer!=SGX_SUCCESS||status!=SGX_SUCCESS){memset(&ida,0,sizeof(ida));memset(&dc,0,sizeof(dc));return 1;}
    ida.DO_ID=dc.DO_ID=1;ida.file_num=dc.file_num=1;
    return 0;
}
