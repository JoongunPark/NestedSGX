#include "Semi_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_secall_test_t {
	int* ms_i;
} ms_secall_test_t;

typedef struct ms_secall_type_char_t {
	char ms_val;
} ms_secall_type_char_t;

typedef struct ms_secall_type_int_t {
	int ms_val;
} ms_secall_type_int_t;

typedef struct ms_secall_type_float_t {
	float ms_val;
} ms_secall_type_float_t;

typedef struct ms_secall_type_double_t {
	double ms_val;
} ms_secall_type_double_t;

typedef struct ms_secall_type_size_t_t {
	size_t ms_val;
} ms_secall_type_size_t_t;

typedef struct ms_secall_type_wchar_t_t {
	wchar_t ms_val;
} ms_secall_type_wchar_t_t;

typedef struct ms_secall_type_struct_t {
	struct struct_poo_t ms_val;
} ms_secall_type_struct_t;

typedef struct ms_secall_type_enum_union_t {
	enum enum_poo_t ms_val1;
	union union_poo_t* ms_val2;
} ms_secall_type_enum_union_t;

typedef struct ms_secall_pointer_user_check_t {
	size_t ms_retval;
	void* ms_val;
	size_t ms_sz;
} ms_secall_pointer_user_check_t;

typedef struct ms_secall_pointer_in_t {
	int* ms_val;
} ms_secall_pointer_in_t;

typedef struct ms_secall_pointer_out_t {
	int* ms_val;
} ms_secall_pointer_out_t;

typedef struct ms_secall_pointer_in_out_t {
	int* ms_val;
} ms_secall_pointer_in_out_t;

typedef struct ms_secall_pointer_string_t {
	char* ms_str;
} ms_secall_pointer_string_t;

typedef struct ms_secall_pointer_string_const_t {
	char* ms_str;
} ms_secall_pointer_string_const_t;

typedef struct ms_secall_pointer_size_t {
	void* ms_ptr;
	size_t ms_len;
} ms_secall_pointer_size_t;

typedef struct ms_secall_pointer_count_t {
	int* ms_arr;
	int ms_cnt;
} ms_secall_pointer_count_t;

typedef struct ms_secall_pointer_isptr_readonly_t {
	buffer_t ms_buf;
	size_t ms_len;
} ms_secall_pointer_isptr_readonly_t;

typedef struct ms_secall_pointer_sizefunc_t {
	char* ms_buf;
} ms_secall_pointer_sizefunc_t;


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



typedef struct ms_secall_function_private_t {
	int ms_retval;
} ms_secall_function_private_t;

typedef struct ms_semi_ocall_print_string_t {
	char* ms_str;
} ms_semi_ocall_print_string_t;

extern void secall_test(int* i);
sgx_status_t SGX_CDECL sgx_secall_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_test_t));
	ms_secall_test_t* ms = SGX_CAST(ms_secall_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_i = ms->ms_i;
	size_t _len_i = sizeof(*_tmp_i);
	int* _in_i = NULL;



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

extern void secall_type_char(char val);
sgx_status_t SGX_CDECL sgx_secall_type_char(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_type_char_t));
	ms_secall_type_char_t* ms = SGX_CAST(ms_secall_type_char_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_type_char(ms->ms_val);


	return status;
}

extern void secall_type_int(int val);
sgx_status_t SGX_CDECL sgx_secall_type_int(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_type_int_t));
	ms_secall_type_int_t* ms = SGX_CAST(ms_secall_type_int_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_type_int(ms->ms_val);


	return status;
}

extern void secall_type_float(float val);
sgx_status_t SGX_CDECL sgx_secall_type_float(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_type_float_t));
	ms_secall_type_float_t* ms = SGX_CAST(ms_secall_type_float_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_type_float(ms->ms_val);


	return status;
}

extern void secall_type_double(double val);
sgx_status_t SGX_CDECL sgx_secall_type_double(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_type_double_t));
	ms_secall_type_double_t* ms = SGX_CAST(ms_secall_type_double_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_type_double(ms->ms_val);


	return status;
}

extern void secall_type_size_t(size_t val);
sgx_status_t SGX_CDECL sgx_secall_type_size_t(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_type_size_t_t));
	ms_secall_type_size_t_t* ms = SGX_CAST(ms_secall_type_size_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_type_size_t(ms->ms_val);


	return status;
}

extern void secall_type_wchar_t(wchar_t val);
sgx_status_t SGX_CDECL sgx_secall_type_wchar_t(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_type_wchar_t_t));
	ms_secall_type_wchar_t_t* ms = SGX_CAST(ms_secall_type_wchar_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_type_wchar_t(ms->ms_val);


	return status;
}

extern void secall_type_struct(struct struct_poo_t val);
sgx_status_t SGX_CDECL sgx_secall_type_struct(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_type_struct_t));
	ms_secall_type_struct_t* ms = SGX_CAST(ms_secall_type_struct_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_type_struct(ms->ms_val);


	return status;
}

extern void secall_type_enum_union(enum enum_poo_t val1, union union_poo_t* val2);
sgx_status_t SGX_CDECL sgx_secall_type_enum_union(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_type_enum_union_t));
	ms_secall_type_enum_union_t* ms = SGX_CAST(ms_secall_type_enum_union_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	union union_poo_t* _tmp_val2 = ms->ms_val2;


	secall_type_enum_union(ms->ms_val1, _tmp_val2);


	return status;
}

extern size_t secall_pointer_user_check(void* val, size_t sz);
sgx_status_t SGX_CDECL sgx_secall_pointer_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_user_check_t));
	ms_secall_pointer_user_check_t* ms = SGX_CAST(ms_secall_pointer_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_val = ms->ms_val;


	ms->ms_retval = secall_pointer_user_check(_tmp_val, ms->ms_sz);


	return status;
}

extern void secall_pointer_in(int* val);
sgx_status_t SGX_CDECL sgx_secall_pointer_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_in_t));
	ms_secall_pointer_in_t* ms = SGX_CAST(ms_secall_pointer_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;



	if (_tmp_val != NULL) {
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_val, _tmp_val, _len_val);
	}
	secall_pointer_in(_in_val);
err:
	if (_in_val) free(_in_val);

	return status;
}

extern void secall_pointer_out(int* val);
sgx_status_t SGX_CDECL sgx_secall_pointer_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_out_t));
	ms_secall_pointer_out_t* ms = SGX_CAST(ms_secall_pointer_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;



	if (_tmp_val != NULL) {
		if ((_in_val = (int*)malloc(_len_val)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_val, 0, _len_val);
	}
	secall_pointer_out(_in_val);
err:
	if (_in_val) {
		memcpy(_tmp_val, _in_val, _len_val);
		free(_in_val);
	}

	return status;
}

extern void secall_pointer_in_out(int* val);
sgx_status_t SGX_CDECL sgx_secall_pointer_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_in_out_t));
	ms_secall_pointer_in_out_t* ms = SGX_CAST(ms_secall_pointer_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;



	if (_tmp_val != NULL) {
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_val, _tmp_val, _len_val);
	}
	secall_pointer_in_out(_in_val);
err:
	if (_in_val) {
		memcpy(_tmp_val, _in_val, _len_val);
		free(_in_val);
	}

	return status;
}

extern void secall_pointer_string(char* str);
sgx_status_t SGX_CDECL sgx_secall_pointer_string(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_string_t));
	ms_secall_pointer_string_t* ms = SGX_CAST(ms_secall_pointer_string_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;



	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	secall_pointer_string(_in_str);
err:
	if (_in_str) {
		memcpy(_tmp_str, _in_str, _len_str);
		free(_in_str);
	}

	return status;
}

extern void secall_pointer_string_const(const char* str);
sgx_status_t SGX_CDECL sgx_secall_pointer_string_const(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_string_const_t));
	ms_secall_pointer_string_const_t* ms = SGX_CAST(ms_secall_pointer_string_const_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;



	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	secall_pointer_string_const((const char*)_in_str);
err:
	if (_in_str) free((void*)_in_str);

	return status;
}

extern void secall_pointer_size(void* ptr, size_t len);
sgx_status_t SGX_CDECL sgx_secall_pointer_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_size_t));
	ms_secall_pointer_size_t* ms = SGX_CAST(ms_secall_pointer_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_ptr = ms->ms_ptr;
	size_t _tmp_len = ms->ms_len;
	size_t _len_ptr = _tmp_len;
	void* _in_ptr = NULL;



	if (_tmp_ptr != NULL) {
		_in_ptr = (void*)malloc(_len_ptr);
		if (_in_ptr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ptr, _tmp_ptr, _len_ptr);
	}
	secall_pointer_size(_in_ptr, _tmp_len);
err:
	if (_in_ptr) {
		memcpy(_tmp_ptr, _in_ptr, _len_ptr);
		free(_in_ptr);
	}

	return status;
}

extern void secall_pointer_count(int* arr, int cnt);
sgx_status_t SGX_CDECL sgx_secall_pointer_count(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_count_t));
	ms_secall_pointer_count_t* ms = SGX_CAST(ms_secall_pointer_count_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	int _tmp_cnt = ms->ms_cnt;
	size_t _len_arr = _tmp_cnt * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	if ((size_t)_tmp_cnt > (SIZE_MAX / sizeof(*_tmp_arr))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}



	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	secall_pointer_count(_in_arr, _tmp_cnt);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

extern void secall_pointer_isptr_readonly(buffer_t buf, size_t len);
sgx_status_t SGX_CDECL sgx_secall_pointer_isptr_readonly(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_isptr_readonly_t));
	ms_secall_pointer_isptr_readonly_t* ms = SGX_CAST(ms_secall_pointer_isptr_readonly_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	buffer_t _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	buffer_t _in_buf = NULL;



	if (_tmp_buf != NULL) {
		_in_buf = (buffer_t)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_buf, _tmp_buf, _len_buf);
	}
	secall_pointer_isptr_readonly(_in_buf, _tmp_len);
err:
	if (_in_buf) free((void*)_in_buf);

	return status;
}

extern void secall_pointer_sizefunc(char* buf);
sgx_status_t SGX_CDECL sgx_secall_pointer_sizefunc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_pointer_sizefunc_t));
	ms_secall_pointer_sizefunc_t* ms = SGX_CAST(ms_secall_pointer_sizefunc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _len_buf = ((_tmp_buf) ? get_buffer_len(_tmp_buf) : 0);
	char* _in_buf = NULL;



	if (_tmp_buf != NULL) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);

		/* check whether the pointer is modified. */
		if (get_buffer_len(_in_buf) != _len_buf) {
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
	}
	secall_pointer_sizefunc(_in_buf);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

extern void socall_pointer_attr();
sgx_status_t SGX_CDECL sgx_socall_pointer_attr(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	socall_pointer_attr();
	return status;
}

extern void secall_array_user_check(int arr[4]);
sgx_status_t SGX_CDECL sgx_secall_array_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_user_check_t));
	ms_secall_array_user_check_t* ms = SGX_CAST(ms_secall_array_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;


	secall_array_user_check(_tmp_arr);


	return status;
}

extern void secall_array_in(int arr[4]);
sgx_status_t SGX_CDECL sgx_secall_array_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_in_t));
	ms_secall_array_in_t* ms = SGX_CAST(ms_secall_array_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;



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

extern void secall_array_out(int arr[4]);
sgx_status_t SGX_CDECL sgx_secall_array_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_out_t));
	ms_secall_array_out_t* ms = SGX_CAST(ms_secall_array_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;



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

extern void secall_array_in_out(int arr[4]);
sgx_status_t SGX_CDECL sgx_secall_array_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_in_out_t));
	ms_secall_array_in_out_t* ms = SGX_CAST(ms_secall_array_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;



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

extern void secall_array_isary(array_t arr);
sgx_status_t SGX_CDECL sgx_secall_array_isary(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_array_isary_t));
	ms_secall_array_isary_t* ms = SGX_CAST(ms_secall_array_isary_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	secall_array_isary((ms->ms_arr != NULL) ? (*ms->ms_arr) : NULL);


	return status;
}

extern void secall_function_calling_convs();
sgx_status_t SGX_CDECL sgx_secall_function_calling_convs(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	secall_function_calling_convs();
	return status;
}

extern void secall_function_public();
sgx_status_t SGX_CDECL sgx_secall_function_public(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	secall_function_public();
	return status;
}

extern int secall_function_private();
sgx_status_t SGX_CDECL sgx_secall_function_private(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_secall_function_private_t));
	ms_secall_function_private_t* ms = SGX_CAST(ms_secall_function_private_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = secall_function_private();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[28];
} g_ecall_table = {
	28,
	{
		{(void*)(uintptr_t)sgx_secall_test, 0},
		{(void*)(uintptr_t)sgx_secall_type_char, 0},
		{(void*)(uintptr_t)sgx_secall_type_int, 0},
		{(void*)(uintptr_t)sgx_secall_type_float, 0},
		{(void*)(uintptr_t)sgx_secall_type_double, 0},
		{(void*)(uintptr_t)sgx_secall_type_size_t, 0},
		{(void*)(uintptr_t)sgx_secall_type_wchar_t, 0},
		{(void*)(uintptr_t)sgx_secall_type_struct, 0},
		{(void*)(uintptr_t)sgx_secall_type_enum_union, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_user_check, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_in, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_out, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_in_out, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_string, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_string_const, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_size, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_count, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_isptr_readonly, 0},
		{(void*)(uintptr_t)sgx_secall_pointer_sizefunc, 0},
		{(void*)(uintptr_t)sgx_socall_pointer_attr, 0},
		{(void*)(uintptr_t)sgx_secall_array_user_check, 0},
		{(void*)(uintptr_t)sgx_secall_array_in, 0},
		{(void*)(uintptr_t)sgx_secall_array_out, 0},
		{(void*)(uintptr_t)sgx_secall_array_in_out, 0},
		{(void*)(uintptr_t)sgx_secall_array_isary, 0},
		{(void*)(uintptr_t)sgx_secall_function_calling_convs, 0},
		{(void*)(uintptr_t)sgx_secall_function_public, 0},
		{(void*)(uintptr_t)sgx_secall_function_private, 1},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][28];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


extern sgx_status_t SGX_CDECL Semi_semi_ocall_print_string(void* pms);
sgx_status_t SGX_CDECL semi_ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_semi_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_semi_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL) ? _len_str : 0;

	__tmp = malloc(ocalloc_size);
	if (__tmp == NULL) {
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_semi_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_semi_ocall_print_string_t));

	if (str != NULL) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = Semi_semi_ocall_print_string(ms);


	return status;
}

