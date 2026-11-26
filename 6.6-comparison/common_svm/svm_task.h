#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Exploratory workload only. Returns a summary, never support-vector records.
int work2_svm_summary(const unsigned char* raw, size_t size, char* output, size_t capacity);
#ifdef __cplusplus
}
#endif
