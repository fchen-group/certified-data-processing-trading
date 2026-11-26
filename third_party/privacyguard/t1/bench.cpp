// Public-fixture processing harness. No attestation claim; never load secrets here.
#include "t1_io.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <stdexcept>
#include <time.h>
#include <sys/stat.h>
static timespec end_time{};
static unsigned endpoints=0;
extern "C" void OCALL_processing_end(){if(clock_gettime(CLOCK_MONOTONIC_RAW,&end_time)!=0)abort();++endpoints;}
extern "C" void OCALL_print_string(const char*){}
static void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
static bool good(sgx_status_t outer,sgx_status_t inner){return outer==SGX_SUCCESS&&inner==SGX_SUCCESS;}
static void seal(const uint8_t key[16],const uint8_t* plain,size_t size,uint8_t* out,uint8_t tag[16]){
    uint8_t nonce[12]={0};int n=0,last=0;
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();require(ctx,"cipher allocation");
    bool ok=EVP_EncryptInit_ex(ctx,EVP_aes_128_gcm(),nullptr,key,nonce)==1&&
        EVP_EncryptUpdate(ctx,out,&n,plain,int(size))==1&&
        EVP_EncryptFinal_ex(ctx,out+n,&last)==1&&EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,tag)==1;
    EVP_CIPHER_CTX_free(ctx);require(ok&&n+last==int(size),"provision encryption");
}
int main(int argc,char** argv){
    if(argc!=4&&argc!=5){fprintf(stderr,"usage: pgbench ENCLAVE FIXTURE OUTPUT [mode]\n");return 2;}
    enclave_info_t enclave{};
#ifndef PG_NATIVE
    bool created=false;
#endif
    try{
        std::string fixture=argv[2],output=argv[3],mode=argc==5?argv[4]:"normal";
        std::vector<uint8_t> key,marker;
        require(pg_read_exact((fixture+"/PUBLIC_TEST_ONLY").c_str(),64,marker)&&
                std::string(marker.begin(),marker.end())=="PUBLIC SYNTHETIC KEYS ONLY\n","public fixture marker");
        require(pg_read_exact((fixture+"/input.key").c_str(),16,key)&&key.size()==16,"fixture key");
#ifdef PG_NATIVE
        enclave.enclave_id=1;
#else
        sgx_launch_token_t token={0};int updated=0;
        require(sgx_create_enclave(argv[1],0,&token,&updated,&enclave.enclave_id,nullptr)==SGX_SUCCESS,"enclave load");
        created=true;
#endif
        // Warm the input ciphertext/tag file cache before timing. Release the
        // temporary buffers; the measured path must read the files again.
        if(mode=="normal"){
            std::vector<uint8_t> warm;
            require(pg_read_exact((fixture+"/input.enc").c_str(),32U<<20,warm),"cipher cache warmup");
            require(pg_read_exact((fixture+"/input.tag").c_str(),16,warm)&&warm.size()==16,"tag cache warmup");
        }
        sgx_status_t inner=SGX_ERROR_UNEXPECTED,outer;
        outer=ECALL_enclave_DO_config(enclave.enclave_id,&inner,mode=="bad-config"?2:1);
        if(mode=="bad-config"){require(!good(outer,inner),"invalid config accepted");}
        else{
            require(good(outer,inner),"DO config");
            uint8_t sessions[32],secret[32],encrypted[32],tag[16];
            require(RAND_bytes(sessions,32)==1&&RAND_bytes(secret,32)==1,"fresh session randomness");
            require(memcmp(sessions,sessions+16,16)!=0,"equal session keys");
            outer=ECALL_prepare_test_sessions(enclave.enclave_id,&inner,sessions,sessions+16);
            require(good(outer,inner),"test session setup");
            for(unsigned role: {2U,1U}){
                size_t size=role==2?16:32;seal(sessions+(role==2?0:16),role==2?key.data():secret,size,encrypted,tag);
                if(mode=="provision-tag"&&role==2)tag[0]^=1;
                outer=ECALL_put_secret_data(enclave.enclave_id,&inner,0,encrypted,size,tag,role);
                if(mode=="provision-tag"&&role==2){require(!good(outer,inner),"bad provisioning tag accepted");break;}
                require(good(outer,inner),"secret provisioning");
            }
            K_result_msg_t ida{};K_result_hash_msg_t dc{};
            if(mode=="repeat-provision"){
                outer=ECALL_put_secret_data(enclave.enclave_id,&inner,0,encrypted,32,tag,1);
                require(!good(outer,inner),"repeat provisioning accepted");
            }else if(mode=="early-delivery"){
                require(pg_make_delivery(&enclave,ida,dc)!=0,"early delivery accepted");
            }else if(mode!="provision-tag"){
                timespec begin{};require(clock_gettime(CLOCK_MONOTONIC_RAW,&begin)==0,"start clock");
                PgOutput result;
                if(mode=="bad-size"||mode=="bad-mac-size"||mode=="small-buffer"){
                    std::vector<uint8_t> input,mac;require(pg_read_exact((fixture+"/input.enc").c_str(),32U<<20,input)&&pg_read_exact((fixture+"/input.tag").c_str(),16,mac)&&mac.size()==16,"test input");
                    uint32_t size=input.size(),declared=size+(mode=="bad-size"),ms=mode=="bad-mac-size"?15:16,len=999;
                    uint8_t cipher[TASK1_RESULT_SIZE],outtag[16];memset(cipher,0x55,sizeof(cipher));memset(outtag,0x55,16);
                    unsigned cap=mode=="small-buffer"?1:TASK1_RESULT_SIZE;
                    outer=ECALL_compute_task1(enclave.enclave_id,&inner,0,1,&declared,&ms,input.data(),size,mac.data(),16,cipher,cap,outtag,&len);
                    require(!good(outer,inner)&&len==0,"invalid sizes accepted");
                    for(unsigned i=0;i<cap;++i)require(cipher[i]==0,"cipher on failure");
                    for(unsigned i=0;i<16;++i)require(outtag[i]==0,"tag on failure");
                }else{
                    int status=pg_read_compute(&enclave,(fixture+"/input.enc").c_str(),(fixture+"/input.tag").c_str(),result);
                    if(mode=="reject-input")require(status!=0&&result.ciphertext.empty(),"invalid input accepted");
                    else{
                        require(status==0,"input processing");
                        if(mode=="repeat-compute")require(pg_read_compute(&enclave,(fixture+"/input.enc").c_str(),(fixture+"/input.tag").c_str(),result)!=0&&result.ciphertext.empty(),"repeat compute accepted");
                        else{
                            require(pg_make_delivery(&enclave,ida,dc)==0&&endpoints==1,"protected delivery");
                            if(mode=="repeat-delivery")require(pg_make_delivery(&enclave,ida,dc)!=0,"repeat delivery accepted");
                            else{
                                require(mode=="normal","unknown mode");
                                double ms=(end_time.tv_sec-begin.tv_sec)*1000.0+(end_time.tv_nsec-begin.tv_nsec)/1e6;
                                require(ms>0,"processing endpoint");
                                require(mkdir(output.c_str(),0700)==0,"new output directory");
                                static_assert(sizeof(ida)==52&&sizeof(dc)==128,"message layout");
                                require(pg_write_exact((output+"/result.enc").c_str(),result.ciphertext.data(),result.ciphertext.size())&&
                                    pg_write_exact((output+"/result.tag").c_str(),result.tag.data(),16)&&
                                    pg_write_exact((output+"/ida.msg").c_str(),reinterpret_cast<uint8_t*>(&ida),sizeof(ida))&&
                                    pg_write_exact((output+"/dc.msg").c_str(),reinterpret_cast<uint8_t*>(&dc),sizeof(dc))&&
                                    pg_write_exact((output+"/public-session-keys.bin").c_str(),sessions,32),"save public test evidence");
                                printf("{\"status\":\"ok\",\"mode\":\"normal\",\"cipher_bytes\":%zu,\"processing_ms_diagnostic_only\":%.9f}\n",result.ciphertext.size(),ms);
                            }
                        }
                    }
                }
            }
            if(mode!="normal"){
                require(pg_make_delivery(&enclave,ida,dc)!=0,"delivery after rejected request");
                for(size_t i=0;i<sizeof(ida);++i)require(reinterpret_cast<uint8_t*>(&ida)[i]==0,"partial key delivery");
                for(size_t i=0;i<sizeof(dc);++i)require(reinterpret_cast<uint8_t*>(&dc)[i]==0,"partial hash delivery");
            }
            OPENSSL_cleanse(sessions,sizeof(sessions));OPENSSL_cleanse(secret,sizeof(secret));
        }
        if(mode!="normal")printf("{\"status\":\"rejected_as_expected\",\"mode\":\"%s\"}\n",mode.c_str());
#ifndef PG_NATIVE
        if(created)require(sgx_destroy_enclave(enclave.enclave_id)==SGX_SUCCESS,"enclave destroy");
#endif
        return 0;
    }catch(const std::exception& e){
#ifndef PG_NATIVE
        if(created)sgx_destroy_enclave(enclave.enclave_id);
#endif
        fprintf(stderr,"pgbench: %s\n",e.what());return 1;
    }
}
