#include "Semi_t.h"

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


typedef struct ms_secall_test_t {
	int* ms_i;
} ms_secall_test_t;

typedef struct ms_secall_array_user_check_t {
	int* ms_arr;
} ms_secall_array_user_check_t;

typedef struct ms_secall_array_in_t {
	int* ms_arr;
} ms_secall_array_in_t;

typedef struct ms_secall_array_out_t {
	int* ms_arr;
} ms_secall_array_out_t;

typedef struct ms_secall_array_in_out_t {
	int* ms_arr;
} ms_secall_array_in_out_t;

typedef struct ms_secall_array_isary_t {
	array_t*  ms_arr;
} ms_secall_array_isary_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_secall_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_test_t));
	ms_secall_test_t* ms = SGX_CAST(ms_secall_test_t*, pms);
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
	secall_test(_in_i);
err:
	if (_in_i) {
		memcpy(_tmp_i, _in_i, _len_i);
		free(_in_i);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_secall_array_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_user_check_t));
	ms_secall_array_user_check_t* ms = SGX_CAST(ms_secall_array_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;


	secall_array_user_check(_tmp_arr);


	return status;
}

static sgx_status_t SGX_CDECL sgx_secall_array_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_in_t));
	ms_secall_array_in_t* ms = SGX_CAST(ms_secall_array_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	secall_array_in(_in_arr);
err:
	if (_in_arr) free(_in_arr);

	return status;
}

static sgx_status_t SGX_CDECL sgx_secall_array_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_out_t));
	ms_secall_array_out_t* ms = SGX_CAST(ms_secall_array_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		if ((_in_arr = (int*)malloc(_len_arr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_arr, 0, _len_arr);
	}
	secall_array_out(_in_arr);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_secall_array_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_in_out_t));
	ms_secall_array_in_out_t* ms = SGX_CAST(ms_secall_array_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	secall_array_in_out(_in_arr);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_secall_array_isary(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_isary_t));
	ms_secall_array_isary_t* ms = SGX_CAST(ms_secall_array_isary_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_array_isary((ms->ms_arr != NULL) ? (*ms->ms_arr) : NULL);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_secall_test, 0},
		{(void*)(uintptr_t)sgx_secall_array_user_check, 0},
		{(void*)(uintptr_t)sgx_secall_array_in, 0},
		{(void*)(uintptr_t)sgx_secall_array_out, 0},
		{(void*)(uintptr_t)sgx_secall_array_in_out, 0},
		{(void*)(uintptr_t)sgx_secall_array_isary, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][6];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

