#include "Semi_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Semi_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Semi = {
	1,
	{
		(void*)Semi_ocall_print_string,
	}
};
sgx_status_t secall_test(sgx_enclave_id_t eid, int* i)
{
	sgx_status_t status;
	ms_secall_test_t ms;
	ms.ms_i = i;
	status = sgx_ecall_semi(eid, 0, &ocall_table_Semi, &ms);
	return status;
}

sgx_status_t secall_array_user_check(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_secall_array_user_check_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall_semi(eid, 1, &ocall_table_Semi, &ms);
	return status;
}

sgx_status_t secall_array_in(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_secall_array_in_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall_semi(eid, 2, &ocall_table_Semi, &ms);
	return status;
}

sgx_status_t secall_array_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_secall_array_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall_semi(eid, 3, &ocall_table_Semi, &ms);
	return status;
}

sgx_status_t secall_array_in_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_secall_array_in_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall_semi(eid, 4, &ocall_table_Semi, &ms);
	return status;
}

sgx_status_t secall_array_isary(sgx_enclave_id_t eid, array_t arr)
{
	sgx_status_t status;
	ms_secall_array_isary_t ms;
	ms.ms_arr = (array_t *)&arr[0];
	status = sgx_ecall_semi(eid, 5, &ocall_table_Semi, &ms);
	return status;
}

