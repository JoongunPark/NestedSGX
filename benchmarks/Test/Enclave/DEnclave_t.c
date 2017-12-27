#include "DEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_test_t {
	int* ms_i;
} ms_ecall_test_t;

static sgx_status_t SGX_CDECL sgx_ecall_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_test_t));
	ms_ecall_test_t* ms = SGX_CAST(ms_ecall_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_i = ms->ms_i;
	size_t _len_i = sizeof(*_tmp_i);
	int* _in_i = NULL;

	CHECK_UNIQUE_POINTER(_tmp_i, _len_i);

	if (_tmp_i != NULL) {
		_in_i = (int*)malloc(_len_i);
		if (_in_i == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_i, _tmp_i, _len_i);
	}
	ecall_test(_in_i);
err:
	if (_in_i) {
		memcpy(_tmp_i, _in_i, _len_i);
		free(_in_i);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table_semi = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_test, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table_semi = {
	0,
};


