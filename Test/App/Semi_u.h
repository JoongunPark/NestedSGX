#ifndef SEMI_U_H__
#define SEMI_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));

sgx_status_t secall_test(sgx_enclave_id_t eid, int* i);
sgx_status_t secall_array_user_check(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t secall_array_in(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t secall_array_out(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t secall_array_in_out(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t secall_array_isary(sgx_enclave_id_t eid, array_t arr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
