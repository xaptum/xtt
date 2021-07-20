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

#include <tss2/tss2_tctildr.h>

#include <string.h>
#include <assert.h>
#include <stdio.h>

int xtt_init_tpm_context(struct xtt_tpm_context *ctx, const char* nameConf)
{
    // tpm2-software's TSS2 implementation seems to have issues
    // if the memory used for the TCTI and SYS contexts aren't zeroed-out before initialization...
    memset(ctx, 0, sizeof(struct xtt_tpm_context));

    if (TSS2_RC_SUCCESS != Tss2_TctiLdr_Initialize(nameConf, &ctx->tcti_context)) {
        return TPM_ERROR;
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
    Tss2_TctiLdr_Finalize(&ctx->tcti_context);
}
