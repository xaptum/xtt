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

#ifndef XTT_TPM_CONTEXT_H
#define XTT_TPM_CONTEXT_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti.h>

typedef enum {
    XTT_TCTI_SOCKET,
    XTT_TCTI_DEVICE,
} xtt_tcti_type;

struct xtt_tpm_params {
    xtt_tcti_type tcti;
    const char *dev_file;
    const char *hostname;
    const char *port;
};

struct xtt_tpm_context {
    unsigned char tcti_context_buffer[256];
    TSS2_TCTI_CONTEXT *tcti_context;
    unsigned char sapi_context_buffer[5120];
    TSS2_SYS_CONTEXT *sapi_context;
};

int xtt_init_tpm_context(struct xtt_tpm_context *ctx, const struct xtt_tpm_params *params);

void xtt_free_tpm_context(struct xtt_tpm_context *ctx);

#ifdef __cplusplus
}
#endif

#endif
