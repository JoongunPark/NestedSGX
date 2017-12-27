#include "Semi_u.h"
#include <errno.h>

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

sgx_status_t SGX_CDECL Semi_semi_ocall_print_string(void* pms)
{
	ms_semi_ocall_print_string_t* ms = SGX_CAST(ms_semi_ocall_print_string_t*, pms);
	semi_ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Semi = {
	1,
	{
		(void*)Semi_semi_ocall_print_string,
	}
};
extern sgx_status_t sgx_secall_test(void* pms);
sgx_status_t secall_test(sgx_enclave_id_t eid, int* i)
{
	sgx_status_t status;
	ms_secall_test_t ms;
	ms.ms_i = i;
	sgx_secall_test(&ms);
	return status;
}

extern sgx_status_t sgx_secall_type_char(void* pms);
sgx_status_t secall_type_char(sgx_enclave_id_t eid, char val)
{
	sgx_status_t status;
	ms_secall_type_char_t ms;
	ms.ms_val = val;
	sgx_secall_type_char(&ms);
	return status;
}

extern sgx_status_t sgx_secall_type_int(void* pms);
sgx_status_t secall_type_int(sgx_enclave_id_t eid, int val)
{
	sgx_status_t status;
	ms_secall_type_int_t ms;
	ms.ms_val = val;
	sgx_secall_type_int(&ms);
	return status;
}

extern sgx_status_t sgx_secall_type_float(void* pms);
sgx_status_t secall_type_float(sgx_enclave_id_t eid, float val)
{
	sgx_status_t status;
	ms_secall_type_float_t ms;
	ms.ms_val = val;
	sgx_secall_type_float(&ms);
	return status;
}

extern sgx_status_t sgx_secall_type_double(void* pms);
sgx_status_t secall_type_double(sgx_enclave_id_t eid, double val)
{
	sgx_status_t status;
	ms_secall_type_double_t ms;
	ms.ms_val = val;
	sgx_secall_type_double(&ms);
	return status;
}

extern sgx_status_t sgx_secall_type_size_t(void* pms);
sgx_status_t secall_type_size_t(sgx_enclave_id_t eid, size_t val)
{
	sgx_status_t status;
	ms_secall_type_size_t_t ms;
	ms.ms_val = val;
	sgx_secall_type_size_t(&ms);
	return status;
}

extern sgx_status_t sgx_secall_type_wchar_t(void* pms);
sgx_status_t secall_type_wchar_t(sgx_enclave_id_t eid, wchar_t val)
{
	sgx_status_t status;
	ms_secall_type_wchar_t_t ms;
	ms.ms_val = val;
	sgx_secall_type_wchar_t(&ms);
	return status;
}

extern sgx_status_t sgx_secall_type_struct(void* pms);
sgx_status_t secall_type_struct(sgx_enclave_id_t eid, struct struct_poo_t val)
{
	sgx_status_t status;
	ms_secall_type_struct_t ms;
	ms.ms_val = val;
	sgx_secall_type_struct(&ms);
	return status;
}

extern sgx_status_t sgx_secall_type_enum_union(void* pms);
sgx_status_t secall_type_enum_union(sgx_enclave_id_t eid, enum enum_poo_t val1, union union_poo_t* val2)
{
	sgx_status_t status;
	ms_secall_type_enum_union_t ms;
	ms.ms_val1 = val1;
	ms.ms_val2 = val2;
	sgx_secall_type_enum_union(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_user_check(void* pms);
sgx_status_t secall_pointer_user_check(sgx_enclave_id_t eid, size_t* retval, void* val, size_t sz)
{
	sgx_status_t status;
	ms_secall_pointer_user_check_t ms;
	ms.ms_val = val;
	ms.ms_sz = sz;
	sgx_secall_pointer_user_check(&ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

extern sgx_status_t sgx_secall_pointer_in(void* pms);
sgx_status_t secall_pointer_in(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_secall_pointer_in_t ms;
	ms.ms_val = val;
	sgx_secall_pointer_in(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_out(void* pms);
sgx_status_t secall_pointer_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_secall_pointer_out_t ms;
	ms.ms_val = val;
	sgx_secall_pointer_out(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_in_out(void* pms);
sgx_status_t secall_pointer_in_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_secall_pointer_in_out_t ms;
	ms.ms_val = val;
	sgx_secall_pointer_in_out(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_string(void* pms);
sgx_status_t secall_pointer_string(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_secall_pointer_string_t ms;
	ms.ms_str = str;
	sgx_secall_pointer_string(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_string_const(void* pms);
sgx_status_t secall_pointer_string_const(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_secall_pointer_string_const_t ms;
	ms.ms_str = (char*)str;
	sgx_secall_pointer_string_const(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_size(void* pms);
sgx_status_t secall_pointer_size(sgx_enclave_id_t eid, void* ptr, size_t len)
{
	sgx_status_t status;
	ms_secall_pointer_size_t ms;
	ms.ms_ptr = ptr;
	ms.ms_len = len;
	sgx_secall_pointer_size(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_count(void* pms);
sgx_status_t secall_pointer_count(sgx_enclave_id_t eid, int* arr, int cnt)
{
	sgx_status_t status;
	ms_secall_pointer_count_t ms;
	ms.ms_arr = arr;
	ms.ms_cnt = cnt;
	sgx_secall_pointer_count(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_isptr_readonly(void* pms);
sgx_status_t secall_pointer_isptr_readonly(sgx_enclave_id_t eid, buffer_t buf, size_t len)
{
	sgx_status_t status;
	ms_secall_pointer_isptr_readonly_t ms;
	ms.ms_buf = (buffer_t)buf;
	ms.ms_len = len;
	sgx_secall_pointer_isptr_readonly(&ms);
	return status;
}

extern sgx_status_t sgx_secall_pointer_sizefunc(void* pms);
sgx_status_t secall_pointer_sizefunc(sgx_enclave_id_t eid, char* buf)
{
	sgx_status_t status;
	ms_secall_pointer_sizefunc_t ms;
	ms.ms_buf = buf;
	sgx_secall_pointer_sizefunc(&ms);
	return status;
}

extern sgx_status_t sgx_socall_pointer_attr(void* pms);
sgx_status_t socall_pointer_attr(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	sgx_socall_pointer_attr(NULL);
	return status;
}

extern sgx_status_t sgx_secall_array_user_check(void* pms);
sgx_status_t secall_array_user_check(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_secall_array_user_check_t ms;
	ms.ms_arr = (int*)arr;
	sgx_secall_array_user_check(&ms);
	return status;
}

extern sgx_status_t sgx_secall_array_in(void* pms);
sgx_status_t secall_array_in(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_secall_array_in_t ms;
	ms.ms_arr = (int*)arr;
	sgx_secall_array_in(&ms);
	return status;
}

extern sgx_status_t sgx_secall_array_out(void* pms);
sgx_status_t secall_array_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_secall_array_out_t ms;
	ms.ms_arr = (int*)arr;
	sgx_secall_array_out(&ms);
	return status;
}

extern sgx_status_t sgx_secall_array_in_out(void* pms);
sgx_status_t secall_array_in_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_secall_array_in_out_t ms;
	ms.ms_arr = (int*)arr;
	sgx_secall_array_in_out(&ms);
	return status;
}

extern sgx_status_t sgx_secall_array_isary(void* pms);
sgx_status_t secall_array_isary(sgx_enclave_id_t eid, array_t arr)
{
	sgx_status_t status;
	ms_secall_array_isary_t ms;
	ms.ms_arr = (array_t *)&arr[0];
	sgx_secall_array_isary(&ms);
	return status;
}

extern sgx_status_t sgx_secall_function_calling_convs(void* pms);
sgx_status_t secall_function_calling_convs(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	sgx_secall_function_calling_convs(NULL);
	return status;
}

extern sgx_status_t sgx_secall_function_public(void* pms);
sgx_status_t secall_function_public(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	sgx_secall_function_public(NULL);
	return status;
}

extern sgx_status_t sgx_secall_function_private(void* pms);
sgx_status_t secall_function_private(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_secall_function_private_t ms;
	sgx_secall_function_private(&ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

