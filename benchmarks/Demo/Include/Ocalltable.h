#ifndef _TABLE__
#define _TABLE__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */
#include <stdio.h> 

#define THRESHOLD 10000

typedef struct _table {
	size_t nr_ocall;
	void *table[20000];
};

#endif 
