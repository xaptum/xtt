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

#include "read_nvram.h"

#include <xtt/tpm/context.h>
#include <xtt/tpm/nvram.h>
#include <xtt/util/util_errors.h>
#include <xtt/util/file_io.h>

#include <stdio.h>

#define MAX_NVRAM_SIZE 768

int read_nvram(const struct xtt_tpm_params *params, const char* outfile, enum xtt_object_name obj_name)
{
    struct xtt_tpm_context ctx;

    int ctx_ret = xtt_init_tpm_context(&ctx, params);
    if (SUCCESS != ctx_ret) {
        fprintf(stderr, "Error initializing TPM context: %d\n", ctx_ret);
        return ctx_ret;
    }

    unsigned char output_data[MAX_NVRAM_SIZE];
    uint16_t output_length;
    printf("Reading object from NVRAM...");
    TSS2_RC read_ret = xtt_read_object(output_data, sizeof(output_data), &output_length, obj_name, ctx.sapi_context);
    if (TSS2_RC_SUCCESS != read_ret) {
        fprintf(stderr, "Bad read_ret: %#X\n", read_ret);
        return TPM_ERROR;
    }

    xtt_save_to_file(output_data, (size_t)output_length, outfile);

    xtt_free_tpm_context(&ctx);

    printf("\tok\n");
    return SUCCESS;
}

