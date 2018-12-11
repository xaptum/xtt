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
#include <xtt/return_codes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH 417 // ServerInitAndAttest
uint16_t max_handshake_server_message_length(void);

#define MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH 750 // Identity_ClientAttest
uint16_t max_handshake_client_message_length(void);

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

xtt_return_code_type
xtt_handshake_client_handle_io(uint16_t bytes_written,
                               uint16_t bytes_read,
                               uint16_t *io_bytes_requested,
                               unsigned char **io_ptr,
                               struct xtt_client_handshake_context* ctx);

xtt_return_code_type
xtt_handshake_server_handle_io(uint16_t bytes_written,
                               uint16_t bytes_read,
                               uint16_t *io_bytes_requested,
                               unsigned char **io_ptr,
                               struct xtt_server_handshake_context* ctx);

xtt_return_code_type
xtt_handshake_client_start(uint16_t *io_bytes_requested,
                           unsigned char **io_ptr,
                           struct xtt_client_handshake_context* ctx);

xtt_return_code_type
xtt_handshake_server_handle_connect(uint16_t *io_bytes_requested,
                                    unsigned char **io_ptr,
                                    struct xtt_server_handshake_context* ctx);

xtt_return_code_type
xtt_handshake_server_build_serverattest(uint16_t *io_bytes_requested,
                                        unsigned char **io_ptr,
                                        struct xtt_server_handshake_context* ctx,
                                        const struct xtt_server_certificate_context* certificate_ctx,
                                        struct xtt_server_cookie_context* cookie_ctx);

xtt_return_code_type
xtt_handshake_client_preparse_serverattest(xtt_certificate_root_id *claimed_root_out,
                                           uint16_t *io_bytes_requested,
                                           unsigned char **io_ptr,
                                           struct xtt_client_handshake_context* handshake_ctx);


xtt_return_code_type
xtt_handshake_client_build_idclientattest(uint16_t *io_bytes_requested,
                                          unsigned char **io_ptr,
                                          const struct xtt_server_root_certificate_context* root_server_certificate,
                                          const xtt_identity_type* requested_client_id,
                                          struct xtt_client_group_context* group_ctx,
                                          struct xtt_client_handshake_context* handshake_ctx);

xtt_return_code_type
xtt_handshake_server_preparse_idclientattest(uint16_t *io_bytes_requested,
                                             unsigned char **io_ptr,
                                             xtt_identity_type* requested_client_id_out,
                                             xtt_group_id* claimed_group_id_out,
                                             struct xtt_server_cookie_context* cookie_ctx,
                                             const struct xtt_server_certificate_context *certificate_ctx,
                                             struct xtt_server_handshake_context* handshake_ctx);

xtt_return_code_type
xtt_handshake_server_verify_groupsignature(uint16_t *io_bytes_requested,
                                           unsigned char **io_ptr,
                                           struct xtt_group_public_key_context* group_pub_key_ctx,
                                           const struct xtt_server_certificate_context *certificate_ctx,
                                           struct xtt_server_handshake_context* handshake_ctx);

xtt_return_code_type
xtt_handshake_server_build_idserverfinished(uint16_t *io_bytes_requested,
                                            unsigned char **io_ptr,
                                            const xtt_identity_type *client_id,
                                            struct xtt_server_handshake_context* handshake_ctx);

xtt_return_code_type
xtt_handshake_client_parse_idserverfinished(uint16_t *io_bytes_requested,
                                            unsigned char **io_ptr,
                                            struct xtt_client_handshake_context* handshake_ctx);

xtt_return_code_type
xtt_server_build_error_msg(uint16_t *io_bytes_requested,
                           unsigned char **io_ptr,
                           struct xtt_server_handshake_context* handshake_ctx);

xtt_return_code_type
xtt_client_build_error_msg(uint16_t *io_bytes_requested,
                           unsigned char **io_ptr,
                           struct xtt_client_handshake_context* handshake_ctx);

#ifdef __cplusplus
}
#endif

#endif
