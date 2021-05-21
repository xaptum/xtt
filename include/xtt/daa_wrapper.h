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

#ifndef XTT_DAA_WRAPPER_H
#define XTT_DAA_WRAPPER_H
#pragma once

#include <xtt/crypto_types.h>
#include <xtt/return_codes.h>

#ifdef USE_TPM
#include <tss2/tss2_sys.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef USE_TPM
int
xtt_daa_sign_lrswTPM(unsigned char *signature_out,
                     const unsigned char *msg,
                     uint16_t msg_len,
                     const unsigned char *basename,
                     uint16_t basename_len,
                     xtt_daa_credential_lrsw *cred,
                     TPM2_HANDLE key_handle,
                     const char *key_password,
                     uint16_t key_password_length,
                     TSS2_TCTI_CONTEXT *tcti_context);
#endif

int
xtt_daa_sign_lrsw(unsigned char *signature_out,
                  const unsigned char *msg,
                  uint16_t msg_len,
                  const unsigned char *basename,
                  uint16_t basename_len,
                  xtt_daa_credential_lrsw *cred,
                  xtt_daa_priv_key_lrsw *priv_key);

int
xtt_daa_verify_lrsw(unsigned char* signature,
                    unsigned char* msg,
                    uint16_t msg_len,
                    unsigned char *basename,
                    uint16_t basename_len,
                    xtt_daa_group_pub_key_lrsw* gpk);

xtt_return_code_type
xtt_daa_access_pseudonym_in_serialized(unsigned char **raw_pseudonym,
                                       uint16_t *raw_pseudonym_length, 
                                       unsigned char *serialized_signature_in);

#ifdef __cplusplus
}
#endif

#endif
