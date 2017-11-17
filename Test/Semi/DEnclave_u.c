#include "DEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_test_t {
	int* ms_i;
} ms_ecall_test_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_DEnclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_test(sgx_enclave_id_t eid, int* i)
{
	sgx_status_t status;
	ms_ecall_test_t ms;
	ms.ms_i = i;
	status = sgx_ecall(eid, 0, &ocall_table_DEnclave, &ms);
	return status;
}

