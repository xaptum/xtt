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

#ifndef XTT_INTERNAL_SIGNATURE_GENERATION_H
#define XTT_INTERNAL_SIGNATURE_GENERATION_H
#pragma once

#include <xtt/context.h>
#include <xtt/crypto_types.h>
#include <xtt/error_codes.h>
#include <xtt/certificates.h>

#ifdef __cplusplus
extern "C" {
#endif

xtt_error_code
generate_server_signature(unsigned char *signature_out,
                          const unsigned char *client_init,
                          const unsigned char *server_initandattest_unencrypted_part,
                          const unsigned char *server_initandattest_encryptedpart_uptosignature,
                          struct xtt_handshake_context *handshake_ctx,
                          const struct xtt_server_certificate_context *certificate_ctx);

xtt_error_code
verify_server_signature(const unsigned char *signature,
                        const xtt_client_id* intended_server_client_id,
                        const struct xtt_server_root_certificate_context* root_server_certificate,
                        const unsigned char *client_init,
                        const unsigned char *server_initandattest_unencrypted_part,
                        const unsigned char *server_initandattest_encryptedpart_uptosignature,
                        struct xtt_client_handshake_context *handshake_ctx);

xtt_error_code
generate_daa_signature(unsigned char *signature_out,
                       const unsigned char *server_cookie,
                       const struct xtt_server_certificate_raw_type *certificate,
                       const unsigned char *server_signature,
                       const unsigned char *identityclientattest_unencrypted_part,
                       const unsigned char *identityclientattest_encryptedpart_uptosignature,
                       struct xtt_handshake_context *handshake_ctx,
                       struct xtt_daa_context *daa_ctx);

xtt_error_code
verify_daa_signature(unsigned char *signature,
                     const unsigned char *server_cookie,
                     const unsigned char *server_signature,
                     const unsigned char *identityclientattest_unencrypted_part,
                     const unsigned char *identityclientattest_encryptedpart_uptosignature,
                     struct xtt_daa_group_public_key_context* daa_group_pub_key_ctx,
                     struct xtt_server_certificate_context *server_certificate_ctx,
                     struct xtt_handshake_context *handshake_ctx);

xtt_error_code
generate_client_longterm_signature(unsigned char *signature_out,
                                   const unsigned char *server_cookie,
                                   const struct xtt_server_certificate_raw_type *certificate,
                                   const unsigned char *server_signature,
                                   const unsigned char *identityclientattest_unencrypted_part,
                                   const unsigned char *identityclientattest_encryptedpart_uptosignature,
                                   struct xtt_client_handshake_context *handshake_ctx);

xtt_error_code
verify_client_longterm_signature(unsigned char *signature,
                                 const unsigned char *server_cookie,
                                 const unsigned char *server_signature,
                                 const unsigned char *identityclientattest_unencrypted_part,
                                 const unsigned char *identityclientattest_encryptedpart_uptosignature,
                                 struct xtt_server_certificate_context *server_certificate_ctx,
                                 struct xtt_server_handshake_context *handshake_ctx);

#ifdef __cplusplus
}
#endif

#endif

