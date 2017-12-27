#include "DEnclave_u.h"
#include <errno.h>

typedef struct ms_decall_test_t {
	int* ms_i;
} ms_decall_test_t;

typedef struct ms_docall_print_string_t {
	char* ms_str;
} ms_docall_print_string_t;

typedef struct ms_dmalloc_test_t {
	void* ms_retval;
	size_t ms_i;
} ms_dmalloc_test_t;

typedef struct ms_dmalloc_t {
	void* ms_retval;
	size_t ms_i;
} ms_dmalloc_t;

typedef struct ms_dfree_t {
	void* ms_i;
} ms_dfree_t;

static sgx_status_t SGX_CDECL DEnclave_docall_print_string(void* pms)
{
	ms_docall_print_string_t* ms = SGX_CAST(ms_docall_print_string_t*, pms);
	docall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL DEnclave_dmalloc_test(void* pms)
{
	ms_dmalloc_test_t* ms = SGX_CAST(ms_dmalloc_test_t*, pms);
	ms->ms_retval = dmalloc_test(ms->ms_i);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL DEnclave_dmalloc(void* pms)
{
	ms_dmalloc_t* ms = SGX_CAST(ms_dmalloc_t*, pms);
	ms->ms_retval = dmalloc(ms->ms_i);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL DEnclave_dfree(void* pms)
{
	ms_dfree_t* ms = SGX_CAST(ms_dfree_t*, pms);
	dfree(ms->ms_i);

	return SGX_SUCCESS;
}

extern struct _table ocall_table_Enclave;

typedef struct _table {
	size_t nr_ocall;
	void * table[20000];
};

_table ocall_table_DEnclave = {
	4,
	{
		(void*)DEnclave_docall_print_string,
		(void*)DEnclave_dmalloc_test,
		(void*)DEnclave_dmalloc,
		(void*)DEnclave_dfree,
	}
};
sgx_status_t decall_test(sgx_enclave_id_t eid, int* i)
{
	_table ocall_table;
	
	memcpy(ocall_table.table,ocall_table_Enclave.table,ocall_table_Enclave.nr_ocall*sizeof(void *));
	
	memcpy(ocall_table.table+10000,ocall_table_DEnclave.table,ocall_table_DEnclave.nr_ocall*sizeof(void *));
	
	ocall_table.nr_ocall = 10000 + ocall_table_DEnclave.nr_ocall;
	sgx_status_t status;
	ms_decall_test_t ms;
	ms.ms_i = i;
	status = sgx_ecall(eid, 0 + 10000, &ocall_table, &ms);
	return status;
}

