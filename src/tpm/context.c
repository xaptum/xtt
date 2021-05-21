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

#include <xtt/util/util_errors.h>
#include <xtt/tpm/context.h>

#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tcti_mssim.h>

#include <string.h>
#include <assert.h>
#include <stdio.h>

int xtt_init_tpm_context(struct xtt_tpm_context *ctx, const struct xtt_tpm_params *params)
{
    // tpm2-software's TSS2 implementation seems to have issues
    // if the memory used for the TCTI and SYS contexts aren't zeroed-out before initialization...
    memset(ctx, 0, sizeof(struct xtt_tpm_context));

    ctx->tcti_context = (TSS2_TCTI_CONTEXT*)ctx->tcti_context_buffer;

    size_t tcti_ctx_size;
    switch (params->tcti) {
        case XTT_TCTI_SOCKET: {
            char config_string[64];
            size_t ret = snprintf(config_string, sizeof(config_string), "host=%s,port=%s", params->hostname, params->port);
            if (ret >= sizeof(config_string)) {
                return TPM_ERROR;
            }
            if (TSS2_RC_SUCCESS != Tss2_Tcti_Mssim_Init(NULL, &tcti_ctx_size, config_string)) {
                return TPM_ERROR;
            }
            assert(tcti_ctx_size < sizeof(ctx->tcti_context_buffer));
            if (TSS2_RC_SUCCESS != Tss2_Tcti_Mssim_Init(ctx->tcti_context, &tcti_ctx_size, config_string)) {
                return TPM_ERROR;
            }
            break;
        }
        case XTT_TCTI_DEVICE:
            if (TSS2_RC_SUCCESS != Tss2_Tcti_Device_Init(NULL, &tcti_ctx_size, params->dev_file)) {
                return TPM_ERROR;
            }
            assert(tcti_ctx_size < sizeof(ctx->tcti_context_buffer));
            if (TSS2_RC_SUCCESS != Tss2_Tcti_Device_Init(ctx->tcti_context, &tcti_ctx_size, params->dev_file)) {
                return TPM_ERROR;
            }
            break;
    }

    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    assert(sapi_ctx_size < sizeof(ctx->sapi_context_buffer));
    ctx->sapi_context = (TSS2_SYS_CONTEXT*)ctx->sapi_context_buffer;
    TSS2_RC ret = Tss2_Sys_Initialize(ctx->sapi_context, sapi_ctx_size, ctx->tcti_context, &abi_version);
    if (TSS2_RC_SUCCESS != ret) {
        return TPM_ERROR;
    }

    return SUCCESS;
}

void xtt_free_tpm_context(struct xtt_tpm_context *ctx)
{
    Tss2_Sys_Finalize(ctx->sapi_context);
    Tss2_Tcti_Finalize(ctx->tcti_context);
}
