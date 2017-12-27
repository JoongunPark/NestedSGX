#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "time.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_clock, ());
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_time, (time_t* timep, int t_len));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_localtime, (const time_t* timep, int t_len));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gmtime_r, (const time_t* timep, int t_len, struct tm* tmp, int tmp_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gettimeofday, (void* tv, int tv_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getsockopt, (int s, int level, int optname, char* optval, int optval_len, int* optlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setsockopt, (int s, int level, int optname, const void* optval, int optlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_socket, (int af, int type, int protocol));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_listen, (int s, int backlog));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_bind, (int s, const void* addr, int addr_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_connect, (int s, const void* addr, int addrlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_accept, (int s, void* addr, int addr_size, int* addrlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_shutdown, (int fd, int how));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_read, (int fd, void* buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_write, (int fd, const void* buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_close, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getenv, (const char* env, int envlen, char* ret_str, int ret_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_start_tls_server(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
