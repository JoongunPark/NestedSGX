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

typedef struct struct_poo_t {
	uint32_t struct_foo_0;
	uint64_t struct_foo_1;
} struct_poo_t;

typedef enum enum_poo_t {
	ENUM_POO_0 = 0,
	ENUM_POO_1 = 1,
} enum_poo_t;

typedef union union_poo_t {
	uint32_t union_foo_0;
	uint32_t union_foo_1;
	uint64_t union_foo_3;
} union_poo_t;

void SGX_UBRIDGE(SGX_NOCONVENTION, semi_ocall_print_string, (const char* str));

sgx_status_t secall_test(sgx_enclave_id_t eid, int* i);
sgx_status_t secall_type_char(sgx_enclave_id_t eid, char val);
sgx_status_t secall_type_int(sgx_enclave_id_t eid, int val);
sgx_status_t secall_type_float(sgx_enclave_id_t eid, float val);
sgx_status_t secall_type_double(sgx_enclave_id_t eid, double val);
sgx_status_t secall_type_size_t(sgx_enclave_id_t eid, size_t val);
sgx_status_t secall_type_wchar_t(sgx_enclave_id_t eid, wchar_t val);
sgx_status_t secall_type_struct(sgx_enclave_id_t eid, struct struct_poo_t val);
sgx_status_t secall_type_enum_union(sgx_enclave_id_t eid, enum enum_poo_t val1, union union_poo_t* val2);
sgx_status_t secall_pointer_user_check(sgx_enclave_id_t eid, size_t* retval, void* val, size_t sz);
sgx_status_t secall_pointer_in(sgx_enclave_id_t eid, int* val);
sgx_status_t secall_pointer_out(sgx_enclave_id_t eid, int* val);
sgx_status_t secall_pointer_in_out(sgx_enclave_id_t eid, int* val);
sgx_status_t secall_pointer_string(sgx_enclave_id_t eid, char* str);
sgx_status_t secall_pointer_string_const(sgx_enclave_id_t eid, const char* str);
sgx_status_t secall_pointer_size(sgx_enclave_id_t eid, void* ptr, size_t len);
sgx_status_t secall_pointer_count(sgx_enclave_id_t eid, int* arr, int cnt);
sgx_status_t secall_pointer_isptr_readonly(sgx_enclave_id_t eid, buffer_t buf, size_t len);
sgx_status_t secall_pointer_sizefunc(sgx_enclave_id_t eid, char* buf);
sgx_status_t socall_pointer_attr(sgx_enclave_id_t eid);
sgx_status_t secall_array_user_check(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t secall_array_in(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t secall_array_out(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t secall_array_in_out(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t secall_array_isary(sgx_enclave_id_t eid, array_t arr);
sgx_status_t secall_function_calling_convs(sgx_enclave_id_t eid);
sgx_status_t secall_function_public(sgx_enclave_id_t eid);
sgx_status_t secall_function_private(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
