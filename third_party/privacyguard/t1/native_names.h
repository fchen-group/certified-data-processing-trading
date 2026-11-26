// Test-only names avoid collision between trusted calls and untrusted wrappers.
#define ECALL_prepare_test_sessions pg_trusted_prepare
#define ECALL_enclave_DO_config pg_trusted_config
#define ECALL_put_secret_data pg_trusted_provision
#define ECALL_compute_task1 pg_trusted_compute
#define ECALL_get_K_result_hashes pg_trusted_deliver
#define OCALL_processing_end pg_native_end
#define OCALL_print_string pg_native_print
