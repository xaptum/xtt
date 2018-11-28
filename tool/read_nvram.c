/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

 #include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tcti_socket.h>
#include <xtt/tpm/nvram.h>
#include <xtt/util/util_errors.h>

#include <getopt.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "read_nvram.h"

#define MAX_NVRAM_SIZE 768

typedef enum {
    XTT_TCTI_SOCKET,
    XTT_TCTI_DEVICE,
} xtt_tcti_type;

struct nvram_context {
    xtt_tcti_type tcti;
    const char *tpm_dev_file;
    const char *tpm_hostname;
    const char *tpm_port;
    const char *out_filename;
    enum xtt_object_name obj_name;
    unsigned char tcti_context_buffer[256];
    TSS2_TCTI_CONTEXT *tcti_context;
    unsigned char sapi_context_buffer[5120];
    TSS2_SYS_CONTEXT *sapi_context;
};

static
void
init_device_tcti(struct nvram_context *ctx);

static
void
init_socket_tcti(struct nvram_context *ctx);

static
void
init_sapi(struct nvram_context *ctx);

static
void
dump_binary_to_file(const char *output_file,
                    unsigned char *binary,
                    size_t size);

int read_nvram(const char* tcti_str, const char* devfile, const char* tpmhostname,
               const char* tpmport, const char* outfile, enum xtt_object_name obj_name)
{
    struct nvram_context ctx;

    if (0 == strcmp(tcti_str, "device")) {
        ctx.tcti = XTT_TCTI_DEVICE;
    } else if (0 == strcmp(tcti_str, "socket")) {
        ctx.tcti = XTT_TCTI_SOCKET;
    } else {
        fprintf(stderr, "Unknown tcti_type '%s'\n", tcti_str);
        return TPM_ERROR;
    }

    ctx.tpm_dev_file = devfile;
    ctx.tpm_hostname = tpmhostname;
    ctx.tpm_port = tpmport;
    ctx.out_filename = outfile;
    ctx.obj_name = obj_name;

    switch (ctx.tcti) {
        case XTT_TCTI_DEVICE:
            init_device_tcti(&ctx);
            break;
        case XTT_TCTI_SOCKET:
            init_socket_tcti(&ctx);
    }

    init_sapi(&ctx);

    unsigned char output_data[MAX_NVRAM_SIZE];
    uint16_t output_length;
    printf("Reading object from NVRAM...");
    TSS2_RC read_ret = xtt_read_object(output_data, sizeof(output_data), &output_length, ctx.obj_name, ctx.sapi_context);
    if (TSS2_RC_SUCCESS != read_ret) {
        fprintf(stderr, "Bad read_ret: %#X\n", read_ret);
        return TPM_ERROR;
    }

    dump_binary_to_file(ctx.out_filename, output_data, output_length);

    Tss2_Sys_Finalize(ctx.sapi_context);
    tss2_tcti_finalize(ctx.tcti_context);

    printf("\tok\n");
    return 0;
}

void
init_device_tcti(struct nvram_context *ctx)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    if (tss2_tcti_getsize_device() >= sizeof(ctx->tcti_context_buffer)) {
        fprintf(stderr, "TCTI device context larger than allocated buffer\n");
        exit(1);
    }
    ctx->tcti_context = (TSS2_TCTI_CONTEXT*)ctx->tcti_context_buffer;

    ret = tss2_tcti_init_device(ctx->tpm_dev_file, strlen(ctx->tpm_dev_file), ctx->tcti_context);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing TCTI device\n");
        exit(1);
    }
}

void
init_socket_tcti(struct nvram_context *ctx)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    if (tss2_tcti_getsize_socket() >= sizeof(ctx->tcti_context_buffer)) {
        fprintf(stderr, "TCTI socket context larger than allocated buffer\n");
        exit(1);
    }
    ctx->tcti_context = (TSS2_TCTI_CONTEXT*)ctx->tcti_context_buffer;

    ret = tss2_tcti_init_socket(ctx->tpm_hostname, ctx->tpm_port, ctx->tcti_context);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing TCTI socket\n");
        exit(1);
    }
}

void
init_sapi(struct nvram_context *ctx)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    if (Tss2_Sys_GetContextSize(0) > sizeof(ctx->sapi_context_buffer)) {
        fprintf(stderr, "SAPI context larger than allocated buffer\n");
        exit(1);
    }
    ctx->sapi_context = (TSS2_SYS_CONTEXT*)ctx->sapi_context_buffer;

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    ret = Tss2_Sys_Initialize(ctx->sapi_context,
                              Tss2_Sys_GetContextSize(0),
                              ctx->tcti_context,
                              &abi_version);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing SAPI context\n");
        exit(1);
    }
}

void
dump_binary_to_file(const char *output_file,
                    unsigned char *binary,
                    size_t size)
{
    FILE *file_ptr = fopen(output_file, "wb");
    if (NULL == file_ptr) {
        fprintf(stderr, "Error opening output file '%s'\n", output_file);
        exit(1);
    }

    size_t write_ret = fwrite(binary, 1, size, file_ptr);
    if (size != write_ret) {
        fprintf(stderr, "Error writing to file\n");
        exit(1);
    }

    fclose(file_ptr);
}
