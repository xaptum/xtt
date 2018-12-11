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

#ifndef XTT_TPM_NVRAM_H
#define XTT_TPM_NVRAM_H
#pragma once

#include <xtt/tpm/context.h>

#ifdef __cplusplus
extern "C" {
#endif

enum xtt_object_name {
    XTT_GROUP_PUBLIC_KEY,
    XTT_CREDENTIAL,
    XTT_CREDENTIAL_SIGNATURE,
    XTT_ROOT_ASN1_CERTIFICATE,
    XTT_BASENAME,
    XTT_ROOT_XTT_CERTIFICATE,
};

TSS2_RC
xtt_read_object(unsigned char* out_buffer,
                uint16_t out_buffer_size,
                uint16_t *out_length,
                enum xtt_object_name object_name,
                struct xtt_tpm_context *tpm_ctx);

TSS2_RC
xtt_read_nvram(unsigned char *out,
               uint16_t size,
               TPM_HANDLE index,
               struct xtt_tpm_context *tpm_ctx);

TSS2_RC
xtt_get_nvram_size(uint16_t *size_out,
                   TPM_HANDLE index,
                   struct xtt_tpm_context *tpm_ctx);

#ifdef __cplusplus
}
#endif

#endif
