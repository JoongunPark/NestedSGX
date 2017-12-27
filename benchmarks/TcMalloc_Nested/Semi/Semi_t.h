#ifndef SEMI_T_H__
#define SEMI_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))


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

size_t get_buffer_len(const char* val);


sgx_status_t SGX_CDECL semi_ocall_print_string(const char* str);

#endif
