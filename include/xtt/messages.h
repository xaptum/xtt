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

#ifndef XTT_MESSAGES_H
#define XTT_MESSAGES_H
#pragma once

#include <xtt/context.h>
#include <xtt/crypto_types.h>
#include <xtt/error_codes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Retrieve the length of a received message.
 *
 * in:
 *      buffer              - Received message
 *
 * Returns:
 *      Length of received message
 */
uint16_t
xtt_get_message_length(const unsigned char* buffer);

/*
 * Retrieve the type of a received message.
 *
 * in:
 *      buffer              - Received message
 *
 * Returns:
 *      MsgType of received message
 */
xtt_msg_type
xtt_get_message_type(const unsigned char* buffer);

/*
 * Build a ClientInit message in the supplied buffer.
 *
 * in:
 *      ctx                 - Already-initialized client_handshake_context.
 *
 * out:
 *      out_buffer          - Buffer into which message will be put.
 *                            Assumed non-NULL and allocated to sufficient size by the caller.
 *
 *      out_length          - Will be populated with length, in bytes, of output ClientInit message.
 *
 * return:
 *      XTT_ERROR_SUCCESS on success
 *      xtt_error_code on failure
 */
xtt_error_code
xtt_build_client_init(unsigned char* out_buffer,
                      uint16_t* out_length,
                      struct xtt_client_handshake_context* ctx);
                      

/*
 * Parse a ClientInit message, then build a ServerInitAndAttest message.
 *
 * out:
 *      out_buffer          - Buffer into which the message will be put.
 *                            Assumed non-NULL and allocated to sufficient size by the caller.
 *
 *      out_length          - Will be populated with length, in bytes, of output message.
 *
 *      ctx_out             - Will be populated with server_handshake_context.
 *                                   Assumed non-NULL.
 *                                   Caller responsible for ensuring pointed-to memory is valid.
 *
 * in:
 *      client_init         - Received message.
 *
 *      certificate_ctx     - A server_certificate_context.
 *                            The algorithm used by this context MUST match that specified
 *                            in the suite_spec in the `handshake_ctx`.
 *
 *      cookie_ctx          - A server_cookie_context.
 *                            It is the caller's responsibility to ensure this cookie_context
 *                            gets rotated frequently-enough.
 *
 * return:
 *      XTT_ERROR_SUCCESS on success
 *      xtt_error_code on failure
 */
xtt_error_code
xtt_build_server_init_and_attest(unsigned char* out_buffer,
                                 uint16_t* out_length,
                                 struct xtt_server_handshake_context* ctx_out,
                                 const unsigned char* client_init,
                                 const struct xtt_server_certificate_context* certificate_ctx,
                                 struct xtt_server_cookie_context* cookie_ctx);

/*
 * Parse a ServerInitAndAttest message,
 * and get the root_id claimed in the server's certificate.
 *
 * Even though the server's signature is not checked in this function,
 * this function _does_ perform the decryption/authentication-check of the AEAD payload.
 *
 * out:
 *      claimed_root_out                        - Certificate_root_id to be used to verify the server's certificate.
 *                                                * Will get set to `xtt_null_server_root_id` on error.
 *
 * in:
 *      server_init_and_attest                  - Received message.
 *
 *      handshake_ctx                           - The client_handshake_context used previously when building the ClientInit message.
 *                                                Will get updated in the process of parsing the message.
 *
 * return:
 *      XTT_ERROR_SUCCESS on success
 *      xtt_error_code on failure
 */
xtt_error_code
xtt_preparse_serverinitandattest(xtt_certificate_root_id *claimed_root_out,
                                 const unsigned char* server_init_and_attest,
                                 struct xtt_client_handshake_context* handshake_ctx);


/*
 * Verify the signature in a ServerInitAndAttest message, then build an IdentityClientAttest message.
 * 
 * The signature verification uses the root_certificate
 * corresponding to the certificate_root_id returned from an earlier call to `xtt_preparse_serverinitandattest`.
 *
 * out:
 *      out_buffer                              - Buffer into which message will be put.
 *                                                Assumed non-NULL and allocated to sufficient size by the caller.
 *
 *      out_length                              - Will be populated with length, in bytes, of output message.
 *
 * in:
 *      server_init_and_attest                  - Received message.
 *
 *      root_server_certificate                 - Root server_certificate corresponding to the certificate_root_id claimed in the server's certificate.
 *
 *      requested_client_id                     - The ClientID that the caller is requesting.
 *                                                If the caller wants the server to choose a ClientID for it,
 *                                                this MUST be set to `xtt_null_client_id`.
 *
 *      intended_server_client_id               - The ClientID of the server that we expect we're talking to.
 *
 *      daa_ctx                                 - The daa_context to use for signing this message.
 *
 *      handshake_ctx                           - The client_handshake_context used previously when building the ClientInit message.
 *                                                Will get updated in the process of parsing the message.
 *
 * return:
 *      XTT_ERROR_SUCCESS on success
 *      xtt_error_code on failure
 */
xtt_error_code
xtt_build_identity_client_attest(unsigned char* out_buffer,
                                 uint16_t* out_length,
                                 const unsigned char* server_init_and_attest,
                                 const struct xtt_server_root_certificate_context* root_server_certificate,
                                 const xtt_client_id* requested_client_id,
                                 const xtt_client_id* intended_server_client_id,
                                 struct xtt_daa_context* daa_ctx,
                                 struct xtt_client_handshake_context* handshake_ctx);

/*
 * Parse a ClientAttest message,
 * before knowing whether it's an IdentityClientAttest or a SessionClientAttest.
 *
 * Even though the client's signature is not checked in this function,
 * this function _does_ perform the decryption/authentication-check of the AEAD payload.
 *
 * out:
 *      client_id                  - If this is an Identity handshake:
 *                                      * The ClientID that the client is requesting.
 *                                        If client_id == `xtt_null_client_id`,
 *                                        the client wants the server to choose a ClientID for it.
 *                                   If this is a Session handshake:
 *                                      * The client's ClientID.
 *
 *      daa_group_id               - If this is an Identity handshake:
 *                                      * The daa_group_id of the client that sent the message.
 *                                   If this is a Session handshake:
 *                                      * SHOULD equal `xtt_null_daa_group_id`.
 *
 * in:
 *      client_attest              - Received message.
 *
 *      cookie_ctx                 - A server_cookie_context.
 *                                   It is the caller's responsibility to ensure this cookie_context
 *
 *      handshake_ctx              - MUST be the same server_handshake_context used previously in this handshake.
 *                                   Assumed non-NULL.
 *                                   Caller responsible for ensuring pointed-to memory is valid.
 *
 * return:
 *      XTT_ERROR_SUCCESS on success
 *      xtt_error_code on failure
 */
xtt_error_code
xtt_pre_parse_client_attest(xtt_client_id* client_id_out,
                            xtt_daa_group_id* daa_group_id_out,
                            const unsigned char* client_attest,
                            struct xtt_server_cookie_context* cookie_ctx,
                            struct xtt_server_handshake_context* handshake_ctx);

/*
 * Validate the DAA signature of an IdentityClientAttest message then build the IdentityServerFinished message.
 *
 * The IdentityClientAttest MUST already have been pre-parsed via the `pre_parse_client_attest` function.
 *
 * On success, the client's longterm_key can be retrieved from the handshake_ctx.
 *
 * out:
 *      out_buffer                  - Buffer into which message will be put.
 *                                    Assumed non-NULL and allocated to sufficient size by the caller.
 *
 *      out_length                  - Will be populated with length, in bytes, of output Identity_ServerFinished message.
 *
 * in:
 *      client_attest               - Received message
 *
 *      client_id                   - The ClientID provisioned to this client.
 *
 *      daa_group_pub_key_ctx       - daa_group_pub_key_context to use to verify the DAA signature.
 *
 *      certificate_ctx             - The server_certificate_context used in creating the ServerInitAndAttest earlier.
 *
 *      handshake_ctx               - MUST be the same server_handshake_context used previously in this handshake.
 *                                    Assumed non-NULL.
 *                                    Caller responsible for ensuring pointed-to memory is valid.
 *                                    Will get updated in the process of building the message.
 *
 * return:
 *      XTT_ERROR_SUCCESS on success
 *      xtt_error_code on failure
 */
xtt_error_code
xtt_build_identity_server_finished(unsigned char *out_buffer,
                                   uint16_t *out_length,
                                   const unsigned char* client_attest,
                                   xtt_client_id *client_id,
                                   struct xtt_daa_group_public_key_context* daa_group_pub_key_ctx,
                                   struct xtt_server_certificate_context *certificate_ctx,
                                   struct xtt_server_handshake_context* handshake_ctx);

/*
 * Validate an IdentityServerFinished message,
 * retrieve the ClientID provisioned by the server,
 * and confirm the ClientID and LongtermKey sent by the server match our expectations.
 *
 * in/out:
 *      client_id                           - If caller didn't request a ClientID in the earlier ClientAttest,
 *                                              * MUST be set to `xtt_null_client_id`,
 *                                                  and on return will be set to CLientID provisioned by server.
 *                                              * Otherwise, caller MUST set to ClientID originally requested in ClientAttest
 *                                                  (in this case, if different from ClientID sent in ServerFinished,
 *                                                  XTT_ERROR code will be returned)
 *
 * in:
 *      identity_server_finished            - Received message.
 *
 *      handshake_ctx                       - The existing client_handshake_context used in this handshake.
 *
 * return:
 *      XTT_ERROR_SUCCESS on success
 *      xtt_error_code on failure
 */
xtt_error_code
xtt_parse_identity_server_finished(xtt_client_id* client_id,
                                   const unsigned char* identity_server_finished,
                                   struct xtt_client_handshake_context* handshake_ctx);

/*
 * Build an Error message.
 *
 * out:
 *      out_buffer          - Buffer into which message will be put.
 *                            Assumed non-NULL and allocated to sufficient size by the caller.
 *
 *      out_length          - Will be populated with length, in bytes, of output ClientInit message.
 *
 * in:
 *      version             - XTT_VERSION used in the current handshake.
 *      
 * return XTT_ERROR_SUCCESS on success
 */
xtt_error_code
build_error_msg(unsigned char *out_buffer,
                uint16_t *out_length,
                xtt_version version);

#ifdef __cplusplus
}
#endif

#endif

