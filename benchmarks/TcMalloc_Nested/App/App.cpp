/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# include <time.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
//#include "../Semi/Semi.h"
#include "Semi_u.h"
#include "Enclave_u.h"

//extern int secall_test(int* i);

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

///* Check error conditions for loading enclave */
//void print_error_message(sgx_status_t ret)
//{
//    size_t idx = 0;
//    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];
//
//    for (idx = 0; idx < ttl; idx++) {
//        if(ret == sgx_errlist[idx].err) {
//            if(NULL != sgx_errlist[idx].sug)
//                printf("Info: %s\n", sgx_errlist[idx].sug);
//            printf("Error: %s\n", sgx_errlist[idx].msg);
//            break;
//        }
//    }
//    
//    if (idx == ttl)
//        printf("Error: Unexpected error occurred.\n");
//}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(int depth)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    if(depth){
    	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    }
    else{
	printf("call sgx_create_enclave \n", global_eid);
    	ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    }
    if (ret != SGX_SUCCESS) {
        //print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s\n", str);
    int i;
    i = 10;
    //ecall_test2(global_eid, &i);	
}

/* OCall functions */
void semi_ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    int i;
    i = 10;

    printf("%s\n", str);
    secall_test(global_eid, &i);	
}

void* omalloc(size_t i){
	void* a;
	a = malloc(i);
	return a;
}

void ofree(void* i){
	free(i);
}

void malloc_test(){
	int* a;
	for(int j=0; j<10000000; j++)
	{
		a = (int *)malloc(sizeof(int)*10);
		free(a);	
	}
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	int i;
	i = 5;
	int* a;
	sgx_status_t ret;

	initialize_enclave(0);
	
	clock_t begin = clock();

	ret = ecall_test(global_eid, &i);	

	clock_t end = clock();
	double time_spent0 = (double)(end-begin) / CLOCKS_PER_SEC;

	ret = ecall_test2(global_eid, &i);	

	clock_t end2 = clock();
	double time_spent1 = (double)(end2-end) / CLOCKS_PER_SEC;

	ret = ecall_test3(global_eid, &i);	

	clock_t end3 = clock();
	double time_spent2 = (double)(end3-end2) / CLOCKS_PER_SEC;

	ret = ecall_test4(global_eid, &i);	

	clock_t end4 = clock();
	double time_spent3 = (double)(end4-end3) / CLOCKS_PER_SEC;

	malloc_test();

	clock_t end5 = clock();
	double time_spent4 = (double)(end5-end4) / CLOCKS_PER_SEC;

	printf("%f time tiem tiemtie\n", time_spent0);
	printf("%f time tiem tiemtie\n", time_spent1);
	printf("%f time tiem tiemtie\n", time_spent2);
	printf("%f time tiem tiemtie\n", time_spent3);
	printf("%f time tiem tiemtie\n", time_spent4);


//	printf("=========================================\n");
////
//	printf("\n%d global_eid\n", global_eid);
//	printf("%d before ecall\n", i);
//	ret = ecall_test(global_eid, &i);	
//	printf("%d after ecall\n", i);
//        //sgx_destroy_enclave(global_eid);
//
//	printf("=========================================\n");
////	initialize_enclave(1);
//	printf("\n%d global_eid\n", global_eid);
//	printf("%d before ecall_semi\n", i);
//	secall_test(global_eid, &i);		
//	printf("%d after ecall_semi\n", i);
//	printf("=========================================\n");
//
////	printf("\n%d global_eid\n", global_eid);
////	printf("%d before ecall\n", i);
////	ret = ecall_test(global_eid, &i);	
////	printf("%d after ecall\n", i);
////        //sgx_destroy_enclave(global_eid);
////	printf("=========================================\n");

	return 0;
}

