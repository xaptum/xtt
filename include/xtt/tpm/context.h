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
#include <tss2/tss2_tcti_socket.h>
#include <tss2/tss2_tcti_device.h>

typedef enum {
    XTT_TCTI_SOCKET,
    XTT_TCTI_DEVICE,
} xtt_tcti_type;

int initialize_tcti(TSS2_TCTI_CONTEXT **tcti_context, xtt_tcti_type tcti_type, const char *dev_file);

int initialize_sapi(TSS2_SYS_CONTEXT *sapi_context, size_t sapi_ctx_size, TSS2_TCTI_CONTEXT *tcti_context);


#ifdef __cplusplus
}
#endif

#endif
