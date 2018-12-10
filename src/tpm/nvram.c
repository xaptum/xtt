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

#include <xtt/tpm/nvram.h>
#include <xtt/tpm/handles.h>

#include <tss2/tss2_sys.h>

#include <string.h>

TSS2_RC
xtt_read_object(unsigned char* out_buffer,
                uint16_t out_buffer_size,
                uint16_t *out_length,
                enum xtt_object_name object_name,
                struct xtt_tpm_context *tpm_ctx)
{
    TPM_HANDLE index = 0;

    switch (object_name) {
        case XTT_GROUP_PUBLIC_KEY:
            index = XTT_GPK_HANDLE;
            break;
        case XTT_CREDENTIAL:
            index = XTT_CRED_HANDLE;
            break;
        case XTT_CREDENTIAL_SIGNATURE:
            index = XTT_CRED_SIG_HANDLE;
            break;
        case XTT_ROOT_ASN1_CERTIFICATE:
            index = XTT_ROOT_ASN1CERT_HANDLE;
            break;
        case XTT_BASENAME:
            index = XTT_BASENAME_HANDLE;
            break;
        case XTT_ROOT_XTT_CERTIFICATE:
            index = XTT_ROOT_XTTCERT_HANDLE;
            break;
    }

    uint16_t size = 0;
    TSS2_RC ret = xtt_get_nvram_size(&size, index, tpm_ctx);
    if (TSS2_RC_SUCCESS != ret)
        return ret;

    if (out_buffer_size < size)
        return TSS2_BASE_RC_INSUFFICIENT_BUFFER;

    *out_length = size;

    return xtt_read_nvram(out_buffer, size, index, tpm_ctx);
}

TSS2_RC
xtt_read_nvram(unsigned char *out,
               uint16_t size,
               TPM_HANDLE index,
               struct xtt_tpm_context *tpm_ctx)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    // We (Xaptum) set AUTHREAD and no password.
    //  This means anyone can read,
    //  by using an empty password and passing the index itself as the auth handle.
    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    uint16_t data_offset = 0;

    while (size > 0) {
        uint16_t bytes_to_read = size;

        TPM2B_MAX_NV_BUFFER nv_data = {.size=0};

        ret = Tss2_Sys_NV_Read(tpm_ctx->sapi_context,
                               index,
                               index,
                               &sessionsData,
                               bytes_to_read,
                               data_offset,
                               &nv_data,
                               &sessionsDataOut);

        if (ret != TSS2_RC_SUCCESS) {
            return ret;
        }

        size -= nv_data.size;

        memcpy(out + data_offset, nv_data.buffer, nv_data.size);
        data_offset += nv_data.size;
    }

    return ret;
}

TSS2_RC
xtt_get_nvram_size(uint16_t *size_out,
                   TPM_HANDLE index,
                   struct xtt_tpm_context *tpm_ctx)
{
    TSS2_SYS_CMD_AUTHS sessionsData = {.cmdAuthsCount = 0};
    TSS2_SYS_RSP_AUTHS sessionsDataOut = {.rspAuthsCount = 0};

    TPM2B_NV_PUBLIC nv_public = {0};

    TPM2B_NAME nv_name = {0};

    TSS2_RC rval = Tss2_Sys_NV_ReadPublic(tpm_ctx->sapi_context,
                                          index,
                                          &sessionsData,
                                          &nv_public,
                                          &nv_name,
                                          &sessionsDataOut);

    if (rval == TSS2_RC_SUCCESS) {
        *size_out = nv_public.nvPublic.dataSize;
    }

    return rval;
}
