#pragma once
#include "operations.h"
#include <array>
#include <vector>
#include <cstdint>
struct PgOutput {
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t,16> tag{};
};
// Shared by the formal CEE host and the isolated public-fixture benchmark.
int pg_read_compute(enclave_info_t* enclave,const char* ciphertext,const char* tag,PgOutput& out);
int pg_make_delivery(enclave_info_t* enclave,K_result_msg_t& ida,K_result_hash_msg_t& dc);
bool pg_read_exact(const char* path,size_t max,std::vector<uint8_t>& bytes);
bool pg_write_exact(const char* path,const uint8_t* data,size_t size);
