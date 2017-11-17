#ifndef SEMI_T_H__
#define SEMI_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void secall_test(int* i);
void secall_array_user_check(int arr[4]);
void secall_array_in(int arr[4]);
void secall_array_out(int arr[4]);
void secall_array_in_out(int arr[4]);
void secall_array_isary(array_t arr);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
