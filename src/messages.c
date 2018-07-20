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

#include <xtt/crypto_wrapper.h>
#include <xtt/crypto_types.h>
#include <xtt/messages.h>
#include <xtt/return_codes.h>

#include "internal/message_utils.h"
#include "internal/byte_utils.h"
#include "internal/server_cookie.h"
#include "internal/signatures.h"
#include "internal/key_derivation.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

uint16_t max_handshake_server_message_length(void)
{
    return MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH;
}

uint16_t max_handshake_client_message_length(void)
{
    return MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH;
}

static
xtt_return_code_type
parse_message_header(uint16_t *length_out,
                     struct xtt_handshake_context *ctx);

static
xtt_return_code_type
parse_client_init(struct xtt_server_handshake_context *ctx_out,
                  const unsigned char* client_init);

static
xtt_return_code_type
parse_server_initandattest(struct xtt_client_handshake_context *handshake_ctx,
                           const unsigned char* server_init_and_attest);

uint16_t
xtt_get_message_length(const unsigned char* buffer)
{
    uint16_t ret;
    bigendian_to_short(xtt_access_length(buffer),
                       &ret);

    return ret;
}

xtt_msg_type
xtt_get_message_type(const unsigned char* buffer)
{
    return *xtt_access_msg_type(buffer);
}

xtt_return_code_type
xtt_handshake_client_handle_io(uint16_t bytes_written,
                               uint16_t bytes_read,
                               uint16_t* io_bytes_requested,
                               unsigned char **io_ptr,
                               struct xtt_client_handshake_context* ctx)
{
    switch (ctx->state) {
        case XTT_CLIENT_HANDSHAKE_STATE_SENDING_CLIENTINIT:
            {
                ctx->base.out_end += bytes_written;
                uint16_t bytes_io_performed_for_this_message = ctx->base.out_end - ctx->base.out_message_start;

                uint16_t message_length = xtt_clientinit_length(ctx->base.version, ctx->base.suite_spec);

                if (bytes_io_performed_for_this_message == message_length) {
                    ctx->state = XTT_CLIENT_HANDSHAKE_STATE_READING_SERVERATTESTHEADER;

                    // Re-set the output buffer pointers
                    ctx->base.out_message_start = ctx->base.out_buffer_start;
                    ctx->base.out_end = ctx->base.out_buffer_start;

                    // Prepare the input buffer pointers
                    ctx->base.in_message_start = ctx->base.in_buffer_start;
                    ctx->base.in_end = ctx->base.in_buffer_start;

                    *io_ptr = ctx->base.in_message_start;

                    *io_bytes_requested = xtt_common_header_length;

                    return XTT_RETURN_WANT_READ;
                } else if (bytes_io_performed_for_this_message < message_length) {
                    *io_ptr = ctx->base.out_end;

                    *io_bytes_requested = message_length - bytes_io_performed_for_this_message;

                    return XTT_RETURN_WANT_WRITE;
                } else {
                    // We wrote too much, which shouldn't happen
                    return XTT_RETURN_BAD_IO_LENGTH;
                }
            }
        case XTT_CLIENT_HANDSHAKE_STATE_READING_SERVERATTESTHEADER:
            {
                ctx->base.in_end += bytes_read;
                uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;

                if (bytes_io_performed_for_this_message >= xtt_common_header_length) {
                    uint16_t message_length;
                    xtt_return_code_type rc = parse_message_header(&message_length, &ctx->base);
                    if (XTT_RETURN_SUCCESS != rc) {
                        return rc;
                    }
                    if (message_length != xtt_serverinitandattest_total_length(ctx->base.version, ctx->base.suite_spec)) {
                        return XTT_RETURN_INCORRECT_LENGTH;
                    }

                    if (bytes_io_performed_for_this_message >= message_length) {
                        ctx->state = XTT_CLIENT_HANDSHAKE_STATE_PREPARSING_SERVERATTEST;

                        // Prepare the output buffer pointers
                        ctx->base.out_message_start = ctx->base.out_buffer_start;
                        ctx->base.out_end = ctx->base.out_buffer_start;

                        return XTT_RETURN_WANT_PREPARSESERVERATTEST;
                    } else {
                        ctx->state = XTT_CLIENT_HANDSHAKE_STATE_READING_SERVERATTEST;
                        *io_ptr = ctx->base.in_end;
                        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
                        return XTT_RETURN_WANT_READ;
                    }
                } else {
                    *io_ptr = ctx->base.in_end;
                    *io_bytes_requested = xtt_common_header_length - bytes_io_performed_for_this_message;
                    return XTT_RETURN_WANT_READ;
                }
            }
        case XTT_CLIENT_HANDSHAKE_STATE_READING_SERVERATTEST:
            {
                ctx->base.in_end += bytes_read;
                uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;

                uint16_t message_length = xtt_serverinitandattest_total_length(ctx->base.version, ctx->base.suite_spec);

                if (bytes_io_performed_for_this_message >= message_length) {
                    ctx->state = XTT_CLIENT_HANDSHAKE_STATE_PREPARSING_SERVERATTEST;

                    // Prepare the output buffer pointers
                    ctx->base.out_message_start = ctx->base.out_buffer_start;
                    ctx->base.out_end = ctx->base.out_buffer_start;

                    return XTT_RETURN_WANT_PREPARSESERVERATTEST;
                } else {
                    *io_ptr = ctx->base.in_end;
                    *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
                    return XTT_RETURN_WANT_READ;
                }
            }
        case XTT_CLIENT_HANDSHAKE_STATE_SENDING_IDCLIENTATTEST:
            {
                ctx->base.out_end += bytes_written;
                uint16_t bytes_io_performed_for_this_message = ctx->base.out_end - ctx->base.out_message_start;

                uint16_t message_length = xtt_identityclientattest_total_length(ctx->base.version, ctx->base.suite_spec);

                if (bytes_io_performed_for_this_message == message_length) {
                    ctx->state = XTT_CLIENT_HANDSHAKE_STATE_READING_IDSERVERFINISHEDHEADER;

                    // Prepare the input buffer pointers
                    ctx->base.in_message_start = ctx->base.in_buffer_start;
                    ctx->base.in_end = ctx->base.in_buffer_start;

                    *io_ptr = ctx->base.in_message_start;

                    *io_bytes_requested = xtt_common_header_length;

                    return XTT_RETURN_WANT_READ;
                } else if (bytes_io_performed_for_this_message < message_length) {
                    *io_ptr = ctx->base.out_end;

                    *io_bytes_requested = message_length - bytes_io_performed_for_this_message;

                    return XTT_RETURN_WANT_WRITE;
                } else {
                    // We wrote too much, which shouldn't happen
                    return XTT_RETURN_BAD_IO_LENGTH;
                }
            }
        case XTT_CLIENT_HANDSHAKE_STATE_READING_IDSERVERFINISHEDHEADER:
            {
                ctx->base.in_end += bytes_read;
                uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;

                if (bytes_io_performed_for_this_message >= xtt_common_header_length) {
                    uint16_t message_length;
                    xtt_return_code_type rc = parse_message_header(&message_length, &ctx->base);
                    if (XTT_RETURN_SUCCESS != rc) {
                        return rc;
                    }
                    if (message_length != xtt_identityserverfinished_total_length(ctx->base.version, ctx->base.suite_spec)) {
                        return XTT_RETURN_INCORRECT_LENGTH;
                    }

                    if (bytes_io_performed_for_this_message >= message_length) {
                        ctx->state = XTT_CLIENT_HANDSHAKE_STATE_PARSING_IDSERVERFINISHED;

                        return XTT_RETURN_WANT_PARSEIDSERVERFINISHED;
                    } else {
                        ctx->state = XTT_CLIENT_HANDSHAKE_STATE_READING_IDSERVERFINISHED;
                        *io_ptr = ctx->base.in_end;
                        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
                        return XTT_RETURN_WANT_READ;
                    }
                } else {
                    *io_ptr = ctx->base.in_end;
                    *io_bytes_requested = xtt_common_header_length - bytes_io_performed_for_this_message;
                    return XTT_RETURN_WANT_READ;
                }
            }
        case XTT_CLIENT_HANDSHAKE_STATE_READING_IDSERVERFINISHED:
            {
                ctx->base.in_end += bytes_read;
                uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;

                uint16_t message_length = xtt_identityserverfinished_total_length(ctx->base.version, ctx->base.suite_spec);

                if (bytes_io_performed_for_this_message >= message_length) {
                    ctx->state = XTT_CLIENT_HANDSHAKE_STATE_PARSING_IDSERVERFINISHED;

                    return XTT_RETURN_WANT_PARSEIDSERVERFINISHED;
                } else {
                    *io_ptr = ctx->base.in_end;
                    *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
                    return XTT_RETURN_WANT_READ;
                }
            }
        default:
            return XTT_RETURN_BAD_HANDSHAKE_ORDER;
    }
}

xtt_return_code_type
xtt_handshake_server_handle_io(uint16_t bytes_written,
                               uint16_t bytes_read,
                               uint16_t* io_bytes_requested,
                               unsigned char **io_ptr,
                               struct xtt_server_handshake_context* ctx)
{
    switch (ctx->state) {
        case XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTINITHEADER:
            {
                ctx->base.in_end += bytes_read;
                uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;

                if (bytes_io_performed_for_this_message >= xtt_common_header_length) {
                    uint16_t message_length;
                    xtt_return_code_type rc = parse_message_header(&message_length, &ctx->base);
                    if (XTT_RETURN_SUCCESS != rc) {
                        return rc;
                    }

                    if (bytes_io_performed_for_this_message >= message_length) {
                        ctx->state = XTT_SERVER_HANDSHAKE_STATE_PARSING_CLIENTINIT_AND_BUILDING_SERVERATTEST;

                        // Prepare the output buffer pointers
                        ctx->base.out_message_start = ctx->base.out_buffer_start;
                        ctx->base.out_end = ctx->base.out_buffer_start;

                        // Set the version and suite_spec in our context,
                        // now that we can find them in the ClientInit header
                        ctx->base.version = *xtt_access_version(ctx->base.in_message_start);
                        xtt_version version_ignore;
                        rc = xtt_get_version(&version_ignore, ctx);
                        if (XTT_RETURN_SUCCESS != rc)
                            return rc;
                        xtt_suite_spec_raw claimed_suite_spec_raw;
                        bigendian_to_short(xtt_clientinit_access_suite_spec(ctx->base.in_message_start, ctx->base.version),
                                           &claimed_suite_spec_raw);
                        ctx->base.suite_spec = claimed_suite_spec_raw;
                        xtt_suite_spec suite_spec_ignore;
                        rc = xtt_get_suite_spec(&suite_spec_ignore, ctx);
                        if (XTT_RETURN_SUCCESS != rc)
                            return rc;

                        return XTT_RETURN_WANT_BUILDSERVERATTEST;
                    } else {
                        ctx->state = XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTINIT;
                        *io_ptr = ctx->base.in_end;
                        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
                        return XTT_RETURN_WANT_READ;
                    }
                } else {
                    *io_ptr = ctx->base.in_end;
                    *io_bytes_requested = xtt_common_header_length - bytes_io_performed_for_this_message;
                    return XTT_RETURN_WANT_READ;
                }
            }
        case XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTINIT:
            {
                ctx->base.in_end += bytes_read;
                uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;

                // Re-read message length
                // (since we don't yet know version and suite_spec, and thus can't calculate it).
                uint16_t message_length;
                xtt_return_code_type rc = parse_message_header(&message_length, &ctx->base);
                if (XTT_RETURN_SUCCESS != rc) {
                    return rc;
                }

                if (bytes_io_performed_for_this_message >= message_length) {
                    ctx->state = XTT_SERVER_HANDSHAKE_STATE_PARSING_CLIENTINIT_AND_BUILDING_SERVERATTEST;

                    // Prepare the output buffer pointers
                    ctx->base.out_message_start = ctx->base.out_buffer_start;
                    ctx->base.out_end = ctx->base.out_buffer_start;

                    // Set the version and suite_spec in our context,
                    // now that we can find them in the ClientInit header
                    ctx->base.version = *xtt_access_version(ctx->base.in_message_start);
                    xtt_version version_ignore;
                    rc = xtt_get_version(&version_ignore, ctx);
                    if (XTT_RETURN_SUCCESS != rc)
                        return rc;
                    xtt_suite_spec_raw claimed_suite_spec_raw;
                    bigendian_to_short(xtt_clientinit_access_suite_spec(ctx->base.in_message_start, ctx->base.version),
                                       &claimed_suite_spec_raw);
                    ctx->base.suite_spec = claimed_suite_spec_raw;
                    xtt_suite_spec suite_spec_ignore;
                    rc = xtt_get_suite_spec(&suite_spec_ignore, ctx);
                    if (XTT_RETURN_SUCCESS != rc)
                        return rc;

                    return XTT_RETURN_WANT_BUILDSERVERATTEST;
                } else {
                    *io_ptr = ctx->base.in_end;
                    *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
                    return XTT_RETURN_WANT_READ;
                }
            }
        case XTT_SERVER_HANDSHAKE_STATE_SENDING_SERVERATTEST:
            {
                ctx->base.out_end += bytes_written;
                uint16_t bytes_io_performed_for_this_message = ctx->base.out_end - ctx->base.out_message_start;

                uint16_t message_length = xtt_serverinitandattest_total_length(ctx->base.version, ctx->base.suite_spec);

                if (bytes_io_performed_for_this_message == message_length) {
                    ctx->state = XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTATTESTHEADER;

                    // Re-set the output buffer pointers
                    ctx->base.out_message_start = ctx->base.out_buffer_start;
                    ctx->base.out_end = ctx->base.out_buffer_start;

                    // Prepare the input buffer pointers
                    ctx->base.in_message_start = ctx->base.in_buffer_start;
                    ctx->base.in_end = ctx->base.in_buffer_start;

                    *io_ptr = ctx->base.in_message_start;

                    *io_bytes_requested = xtt_common_header_length;

                    return XTT_RETURN_WANT_READ;
                } else if (bytes_io_performed_for_this_message < message_length) {
                    *io_ptr = ctx->base.out_end;

                    *io_bytes_requested = message_length - bytes_io_performed_for_this_message;

                    return XTT_RETURN_WANT_WRITE;
                } else {
                    // We wrote too much, which shouldn't happen
                    return XTT_RETURN_BAD_IO_LENGTH;
                }
            }
        case XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTATTESTHEADER:
            {
                ctx->base.in_end += bytes_read;
                uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;

                if (bytes_io_performed_for_this_message >= xtt_common_header_length) {
                    // TODO: Get the *actual* type of the client_attest (id vs session) and proceed accordingly
                    uint16_t message_length;
                    xtt_return_code_type rc = parse_message_header(&message_length, &ctx->base);
                    if (XTT_RETURN_SUCCESS != rc) {
                        return rc;
                    }
                    if (message_length != xtt_identityclientattest_total_length(ctx->base.version, ctx->base.suite_spec)) {
                        return XTT_RETURN_INCORRECT_LENGTH;
                    }

                    if (bytes_io_performed_for_this_message >= message_length) {
                        ctx->state = XTT_SERVER_HANDSHAKE_STATE_PREPARSING_IDCLIENTATTEST;

                        // Prepare the output buffer pointers
                        ctx->base.out_message_start = ctx->base.out_buffer_start;
                        ctx->base.out_end = ctx->base.out_buffer_start;

                        return XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST;
                    } else {
                        ctx->state = XTT_SERVER_HANDSHAKE_STATE_READING_IDCLIENTATTEST;
                        *io_ptr = ctx->base.in_end;
                        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
                        return XTT_RETURN_WANT_READ;
                    }
                } else {
                    *io_ptr = ctx->base.in_end;
                    *io_bytes_requested = xtt_common_header_length - bytes_io_performed_for_this_message;
                    return XTT_RETURN_WANT_READ;
                }
            }
        case XTT_SERVER_HANDSHAKE_STATE_READING_IDCLIENTATTEST:
            {
                ctx->base.in_end += bytes_read;
                uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;

                uint16_t message_length = xtt_identityclientattest_total_length(ctx->base.version, ctx->base.suite_spec);

                if (bytes_io_performed_for_this_message >= message_length) {
                    ctx->state = XTT_SERVER_HANDSHAKE_STATE_PREPARSING_IDCLIENTATTEST;

                    // Prepare the output buffer pointers
                    ctx->base.out_message_start = ctx->base.out_buffer_start;
                    ctx->base.out_end = ctx->base.out_buffer_start;

                    return XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST;
                } else {
                    *io_ptr = ctx->base.in_end;
                    *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
                    return XTT_RETURN_WANT_READ;
                }
            }
        case XTT_SERVER_HANDSHAKE_STATE_SENDING_IDSERVERFINISHED:
            {
                ctx->base.out_end += bytes_written;
                uint16_t bytes_io_performed_for_this_message = ctx->base.out_end - ctx->base.out_message_start;

                uint16_t message_length = xtt_identityserverfinished_total_length(ctx->base.version, ctx->base.suite_spec);

                if (bytes_io_performed_for_this_message == message_length) {
                    ctx->state = XTT_SERVER_HANDSHAKE_STATE_FINISHED;
                    return XTT_RETURN_HANDSHAKE_FINISHED;
                } else if (bytes_io_performed_for_this_message < message_length) {
                    *io_ptr = ctx->base.out_end;

                    *io_bytes_requested = message_length - bytes_io_performed_for_this_message;

                    return XTT_RETURN_WANT_WRITE;
                } else {
                    // We wrote too much, which shouldn't happen
                    return XTT_RETURN_BAD_IO_LENGTH;
                }
            }
        default:
            return XTT_RETURN_BAD_HANDSHAKE_ORDER;
    }
}

xtt_return_code_type
xtt_handshake_client_start(uint16_t* io_bytes_requested,
                           unsigned char **io_ptr,
                           struct xtt_client_handshake_context* ctx)
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;

    // 0) Ensure we're in the correct state
    if (XTT_CLIENT_HANDSHAKE_STATE_START != ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Set message type.
    *xtt_access_msg_type(ctx->base.out_message_start) = XTT_CLIENTINIT_MSG;

    // 2) Set length.
    short_to_bigendian(xtt_clientinit_length(ctx->base.version, ctx->base.suite_spec),
                       xtt_access_length(ctx->base.out_message_start));

    // 3) Set version.
    *xtt_access_version(ctx->base.out_message_start) = ctx->base.version;

    // 4) Set suite spec.
    short_to_bigendian(ctx->base.suite_spec,
                       xtt_clientinit_access_suite_spec(ctx->base.out_message_start, ctx->base.version));

    // 5) Generate nonce.
    xtt_crypto_get_random(xtt_clientinit_access_nonce(ctx->base.out_message_start, ctx->base.version)->data,
                         sizeof(xtt_signing_nonce));

    // 6) Set Diffie-Hellman key pair.
    // Key pair is assumed to have been generated previously
    // by a call to the init function for the handshake context.
    ctx->base.copy_dh_pubkey(xtt_clientinit_access_ecdhe_key(ctx->base.out_message_start,
                                                             ctx->base.version),
                             NULL,
                             &ctx->base);

    // 7) Report ClientInit message length.
    *io_bytes_requested = xtt_clientinit_length(ctx->base.version, ctx->base.suite_spec);

    // 8) Set io_ptr.
    *io_ptr = ctx->base.out_message_start;

    // 9) Copy ClientInit message for later parsing of response.
    assert(sizeof(ctx->base.client_init_buffer) >= *io_bytes_requested);
    memcpy(ctx->base.client_init_buffer, ctx->base.out_message_start, *io_bytes_requested);

    // 10) Advance current state
    ctx->state = XTT_CLIENT_HANDSHAKE_STATE_SENDING_CLIENTINIT;

finish:
    if (XTT_RETURN_SUCCESS == rc) {
        return XTT_RETURN_WANT_WRITE;
    } else {
        (void)xtt_client_build_error_msg(io_bytes_requested, io_ptr, ctx);

        // 13) Set io_ptr
        *io_ptr = ctx->base.out_message_start;

        ctx->state = XTT_CLIENT_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
xtt_handshake_server_handle_connect(uint16_t *io_bytes_requested,
                                    unsigned char **io_ptr,
                                    struct xtt_server_handshake_context* ctx)
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;

    // 0) Ensure we're in the correct state
    if (XTT_SERVER_HANDSHAKE_STATE_START != ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Report header length
    *io_bytes_requested = xtt_common_header_length;

    // 2) Set io_ptr to beginning of ctx->base.in_buffer
    *io_ptr = ctx->base.in_message_start;

    // 3) Set current state
    ctx->state = XTT_SERVER_HANDSHAKE_STATE_READING_CLIENTINITHEADER;

finish:
    if (XTT_RETURN_SUCCESS == rc) {
        return XTT_RETURN_WANT_READ;
    } else {
        (void)xtt_server_build_error_msg(io_bytes_requested, io_ptr, ctx);

        // 13) Set io_ptr
        *io_ptr = ctx->base.out_message_start;

        ctx->state = XTT_SERVER_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
xtt_handshake_server_build_serverattest(uint16_t* io_bytes_requested,
                                        unsigned char **io_ptr,
                                        struct xtt_server_handshake_context* ctx,
                                        const struct xtt_server_certificate_context* certificate_ctx,
                                        struct xtt_server_cookie_context* cookie_ctx)
{
    xtt_return_code_type rc;

    // 0i) Ensure we've read enough
    uint16_t bytes_io_performed_for_this_message = ctx->base.in_end - ctx->base.in_message_start;
    // Re-read message length
    // (since we don't yet know version and suite_spec, and thus can't calculate it).
    uint16_t message_length;
    if (XTT_RETURN_SUCCESS != parse_message_header(&message_length, &ctx->base)) {
        rc = XTT_RETURN_RECEIVED_ERROR_MSG;
        goto finish;
    }
    if (bytes_io_performed_for_this_message < message_length) {
        *io_ptr = ctx->base.in_end;
        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
        return XTT_RETURN_WANT_READ;
    }

    // 0ii) Ensure we're in the correct state
    if (XTT_SERVER_HANDSHAKE_STATE_PARSING_CLIENTINIT_AND_BUILDING_SERVERATTEST != ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Parse ClientInit and initialize our handshake_context using it.
    rc = parse_client_init(ctx, ctx->base.in_message_start);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

    // 2) Set message type.
    *xtt_access_msg_type(ctx->base.out_message_start) = XTT_SERVERINITANDATTEST_MSG;

    // 3) Set length.
    short_to_bigendian(xtt_serverinitandattest_total_length(ctx->base.version, ctx->base.suite_spec),
                       xtt_access_length(ctx->base.out_message_start));

    // 4) Set version.
    *xtt_access_version(ctx->base.out_message_start) = ctx->base.version;

    // 5) Set suite spec.
    short_to_bigendian(ctx->base.suite_spec,
                       xtt_serverinitandattest_access_suite_spec(ctx->base.out_message_start, ctx->base.version));

    // 6) Copy own Diffie-Hellman public key.
    ctx->base.copy_dh_pubkey(xtt_serverinitandattest_access_ecdhe_key(ctx->base.out_message_start,
                                                                          ctx->base.version),
                                 NULL,
                                 &ctx->base);

    // 7) Generate ServerCookie
    rc = build_server_cookie(xtt_serverinitandattest_access_server_cookie(ctx->base.out_message_start,
                                                                          ctx->base.version,
                                                                          ctx->base.suite_spec),
                             &ctx->base,
                             cookie_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

    // 8) Copy own certificate.
    memcpy(xtt_encrypted_serverinitandattest_access_certificate(ctx->base.buffer,
                                                                ctx->base.version),
           certificate_ctx->serialized_certificate,
           xtt_server_certificate_length(ctx->base.suite_spec));

    // 9) Create signature.
    rc = generate_server_signature(xtt_encrypted_serverinitandattest_access_signature(ctx->base.buffer,
                                                                                      ctx->base.version,
                                                                                      ctx->base.suite_spec),
                                   ctx->base.in_message_start,
                                   ctx->base.out_message_start,
                                   ctx->base.buffer,
                                   &ctx->base,
                                   certificate_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

    // 9ii) Copy signature for later, too.
    memcpy(ctx->base.server_signature_buffer,
           xtt_encrypted_serverinitandattest_access_signature(ctx->base.buffer,
                                                              ctx->base.version,
                                                              ctx->base.suite_spec),
           certificate_ctx->signature_length);

    // 10) Run Diffie-Hellman and get handshake AEAD keys.
    // TODO: Move this earlier, in case it fails?
    rc = derive_handshake_keys(&ctx->base,
                               ctx->base.in_message_start,
                               ctx->base.out_message_start,
                               xtt_serverinitandattest_access_server_cookie(ctx->base.out_message_start,
                                                                            ctx->base.version,
                                                                            ctx->base.suite_spec),
                               xtt_clientinit_access_ecdhe_key(ctx->base.in_message_start,
                                                               ctx->base.version),
                               0);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

    // 11) AEAD encrypt the message
    uint16_t encrypted_len;
    rc = ctx->base.encrypt(ctx->base.out_message_start + xtt_serverinitandattest_unencrypted_part_length(ctx->base.version,
                                                                                            ctx->base.suite_spec),
                               &encrypted_len,
                               ctx->base.buffer,
                               xtt_serverinitandattest_encrypted_part_length(ctx->base.version,
                                                                             ctx->base.suite_spec),
                               ctx->base.out_message_start,
                               xtt_serverinitandattest_unencrypted_part_length(ctx->base.version,
                                                                               ctx->base.suite_spec),
                               &ctx->base);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_RETURN_SUCCESS == rc) {
        // 12) Report ServerInitAndAttest message length.
        *io_bytes_requested = xtt_serverinitandattest_unencrypted_part_length(ctx->base.version, ctx->base.suite_spec)
                        + encrypted_len;
        assert(xtt_serverinitandattest_total_length(ctx->base.version, ctx->base.suite_spec) == *io_bytes_requested);

        // 13) Set io_ptr
        *io_ptr = ctx->base.out_message_start;

        // 14) Reset input buffer pointers
        ctx->base.in_message_start += xtt_clientinit_length(ctx->base.version, ctx->base.suite_spec);
        if (ctx->base.in_message_start >= ctx->base.in_end) {
            ctx->base.in_message_start = ctx->base.in_buffer_start;
            ctx->base.in_end = ctx->base.in_buffer_start;
        }

        // 15) Advance current state
        ctx->state = XTT_SERVER_HANDSHAKE_STATE_SENDING_SERVERATTEST;

        return XTT_RETURN_WANT_WRITE;
    } else {
        (void)xtt_server_build_error_msg(io_bytes_requested, io_ptr, ctx);

        // 13) Set io_ptr
        *io_ptr = ctx->base.out_message_start;

        ctx->state = XTT_SERVER_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
xtt_handshake_client_preparse_serverattest(xtt_certificate_root_id *claimed_root_out,
                                           uint16_t *io_bytes_requested,
                                           unsigned char **io_ptr,
                                           struct xtt_client_handshake_context* handshake_ctx)
{
    xtt_return_code_type rc;

    // 0i) Ensure we've read enough
    uint16_t bytes_io_performed_for_this_message = handshake_ctx->base.in_end - handshake_ctx->base.in_message_start;
    uint16_t message_length = xtt_serverinitandattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec);
    if (XTT_RETURN_SUCCESS != parse_message_header(&message_length, &handshake_ctx->base)) {
        rc = XTT_RETURN_RECEIVED_ERROR_MSG;
        goto finish;
    }
    if (bytes_io_performed_for_this_message < message_length) {
        *io_ptr = handshake_ctx->base.in_end;
        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
        return XTT_RETURN_WANT_READ;
    }

    // 0ii) Ensure we're in the correct state
    if (XTT_CLIENT_HANDSHAKE_STATE_PREPARSING_SERVERATTEST != handshake_ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Parse ServerInitAndAttest,
    //  get the handshake AEAD keys,
    //  and AEAD-decrypt-and-authenticate the ServerInitAndAttest.
    rc = parse_server_initandattest(handshake_ctx, handshake_ctx->base.in_message_start);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_RETURN_SUCCESS == rc) {
        //  2) Get the root_id claimed in the server's certificate.
        unsigned char *server_initandattest_decryptedpart = handshake_ctx->base.server_initandattest_buffer;
        memcpy(claimed_root_out->data,
               xtt_server_certificate_access_rootid(xtt_encrypted_serverinitandattest_access_certificate(server_initandattest_decryptedpart,
                                                                                                         handshake_ctx->base.version)),
               sizeof(xtt_certificate_root_id));

        // 3) Advance state
        // // TODO Set state based on what type of handshake we want (id vs session)
        handshake_ctx->state = XTT_CLIENT_HANDSHAKE_STATE_BUILDING_IDCLIENTATTEST;

        return XTT_RETURN_WANT_BUILDIDCLIENTATTEST;
    } else {
        *claimed_root_out = xtt_null_server_root_id;

        (void)xtt_client_build_error_msg(io_bytes_requested, io_ptr, handshake_ctx);

        // 13) Set io_ptr
        *io_ptr = handshake_ctx->base.out_message_start;

        handshake_ctx->state = XTT_CLIENT_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
xtt_handshake_client_build_idclientattest(uint16_t *io_bytes_requested,
                                          unsigned char **io_ptr,
                                          const struct xtt_server_root_certificate_context* root_server_certificate,
                                          const xtt_identity_type* requested_client_id,
                                          const xtt_identity_type* intended_server_identity,
                                          struct xtt_client_group_context* group_ctx,
                                          struct xtt_client_handshake_context* handshake_ctx)
{
    xtt_return_code_type rc;
    // 0i) Ensure we've read enough
    uint16_t bytes_io_performed_for_this_message = handshake_ctx->base.in_end - handshake_ctx->base.in_message_start;
    uint16_t message_length = xtt_serverinitandattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec);
    if (XTT_RETURN_SUCCESS != parse_message_header(&message_length, &handshake_ctx->base)) {
        rc = XTT_RETURN_RECEIVED_ERROR_MSG;
        goto finish;
    }
    if (bytes_io_performed_for_this_message < message_length) {
        *io_ptr = handshake_ctx->base.in_end;
        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
        return XTT_RETURN_WANT_READ;
    }
    // 0ii) Ensure we're in the correct state
    if (XTT_CLIENT_HANDSHAKE_STATE_BUILDING_IDCLIENTATTEST != handshake_ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Check server signature
    rc = verify_server_signature(xtt_encrypted_serverinitandattest_access_signature(handshake_ctx->base.server_initandattest_buffer,
                                                                                    handshake_ctx->base.version,
                                                                                    handshake_ctx->base.suite_spec),
                                 intended_server_identity,
                                 root_server_certificate,
                                 handshake_ctx->base.client_init_buffer,
                                 handshake_ctx->base.in_message_start,
                                 handshake_ctx->base.server_initandattest_buffer,
                                 handshake_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

    // 2) Set message type.
    *xtt_access_msg_type(handshake_ctx->base.out_message_start) = XTT_ID_CLIENTATTEST_MSG;

    // 3) Set length.
    short_to_bigendian(xtt_identityclientattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec),
                       xtt_access_length(handshake_ctx->base.out_message_start));

    // 4) Set version.
    *xtt_access_version(handshake_ctx->base.out_message_start) = handshake_ctx->base.version;

    // 5) Set suite spec.
    short_to_bigendian(handshake_ctx->base.suite_spec,
                       xtt_identityclientattest_access_suite_spec(handshake_ctx->base.out_message_start, handshake_ctx->base.version));

    // 6) Copy server cookie
    memcpy(xtt_identityclientattest_access_servercookie(handshake_ctx->base.out_message_start, handshake_ctx->base.version),
           xtt_serverinitandattest_access_server_cookie(handshake_ctx->base.in_message_start,
                                                        handshake_ctx->base.version,
                                                        handshake_ctx->base.suite_spec),
           sizeof(xtt_server_cookie));

    // 7) Copy longterm public key in.
    handshake_ctx->copy_longterm_key(xtt_encrypted_identityclientattest_access_longtermkey(handshake_ctx->base.buffer,
                                                                                           handshake_ctx->base.version),
                                     NULL,
                                     handshake_ctx);

    // 8) Create longterm_signature with longterm key.
    rc = generate_client_longterm_signature(xtt_encrypted_identityclientattest_access_longtermsignature(handshake_ctx->base.buffer,
                                                                                                        handshake_ctx->base.version,
                                                                                                        handshake_ctx->base.suite_spec),
                                (unsigned char*)xtt_serverinitandattest_access_server_cookie(handshake_ctx->base.in_message_start,
                                                                                             handshake_ctx->base.version,
                                                                                             handshake_ctx->base.suite_spec),
                                xtt_encrypted_serverinitandattest_access_certificate(handshake_ctx->base.server_initandattest_buffer,
                                                                                     handshake_ctx->base.version),
                                xtt_encrypted_serverinitandattest_access_signature(handshake_ctx->base.server_initandattest_buffer,
                                                                                   handshake_ctx->base.version,
                                                                                   handshake_ctx->base.suite_spec),
                                handshake_ctx->base.out_message_start,
                                handshake_ctx->base.buffer,
                                handshake_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

    // 9) Copy GID.
    memcpy(xtt_encrypted_identityclientattest_access_gid(handshake_ctx->base.buffer,
                                                         handshake_ctx->base.version,
                                                         handshake_ctx->base.suite_spec),
           group_ctx->gid.data,
           sizeof(xtt_group_id));

    // 10) Copy my clientID.
    memcpy(xtt_encrypted_identityclientattest_access_id(handshake_ctx->base.buffer,
                                                        handshake_ctx->base.version,
                                                        handshake_ctx->base.suite_spec),
           requested_client_id->data,
           sizeof(xtt_identity_type));
    // 10ii) Copy requested clientID to my context, too
    memcpy(handshake_ctx->identity.data,
           requested_client_id->data,
           sizeof(xtt_identity_type));

    // 11) Create DAA signature.
    rc = generate_daa_signature(xtt_encrypted_identityclientattest_access_daasignature(handshake_ctx->base.buffer,
                                                                                       handshake_ctx->base.version,
                                                                                       handshake_ctx->base.suite_spec),
                                (unsigned char*)xtt_serverinitandattest_access_server_cookie(handshake_ctx->base.in_message_start,
                                                                                             handshake_ctx->base.version,
                                                                                             handshake_ctx->base.suite_spec),
                                xtt_encrypted_serverinitandattest_access_certificate(handshake_ctx->base.server_initandattest_buffer,
                                                                                     handshake_ctx->base.version),
                                xtt_encrypted_serverinitandattest_access_signature(handshake_ctx->base.server_initandattest_buffer,
                                                                                   handshake_ctx->base.version,
                                                                                   handshake_ctx->base.suite_spec),
                                handshake_ctx->base.out_message_start,
                                handshake_ctx->base.buffer,
                                &handshake_ctx->base,
                                group_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;
    // 11i) Copy pseudonym in our context
    handshake_ctx->copy_in_my_pseudonym(handshake_ctx,
                                        xtt_encrypted_identityclientattest_access_daasignature(handshake_ctx->base.buffer,
                                                                                               handshake_ctx->base.version,
                                                                                               handshake_ctx->base.suite_spec));

    // 12) AEAD encrypt the message
    uint16_t encrypted_len;
    rc = handshake_ctx->base.encrypt(handshake_ctx->base.out_message_start + xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version),
                                     &encrypted_len,
                                     handshake_ctx->base.buffer,
                                     xtt_identityclientattest_encrypted_part_length(handshake_ctx->base.version,
                                                                                    handshake_ctx->base.suite_spec),
                                     handshake_ctx->base.out_message_start,
                                     xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version),
                                     &handshake_ctx->base);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_RETURN_SUCCESS == rc) {
        // 13) Report Identity_CLientAttest message length.
        *io_bytes_requested = xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version)
                        + encrypted_len;
        assert(xtt_identityclientattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec) == *io_bytes_requested);

        // 13) Set io_ptr
        *io_ptr = handshake_ctx->base.out_message_start;

        // 14) Advance state
        handshake_ctx->state = XTT_CLIENT_HANDSHAKE_STATE_SENDING_IDCLIENTATTEST;

        return XTT_RETURN_WANT_WRITE;
    } else {
        (void)xtt_client_build_error_msg(io_bytes_requested, io_ptr, handshake_ctx);

        // 13) Set io_ptr
        *io_ptr = handshake_ctx->base.out_message_start;

        handshake_ctx->state = XTT_CLIENT_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
xtt_handshake_server_preparse_idclientattest(uint16_t *io_bytes_requested,
                                             unsigned char **io_ptr,
                                             xtt_identity_type* requested_client_id_out,
                                             xtt_group_id* claimed_group_id_out,
                                             struct xtt_server_cookie_context* cookie_ctx,
                                             const struct xtt_server_certificate_context *certificate_ctx,
                                             struct xtt_server_handshake_context* handshake_ctx)
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;

    // 0i) Ensure we've read enough
    uint16_t bytes_io_performed_for_this_message = handshake_ctx->base.in_end - handshake_ctx->base.in_message_start;
    uint16_t message_length = xtt_identityclientattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec);
    if (XTT_RETURN_SUCCESS != parse_message_header(&message_length, &handshake_ctx->base)) {
        rc = XTT_RETURN_RECEIVED_ERROR_MSG;
        goto finish;
    }
    if (bytes_io_performed_for_this_message < message_length) {
        *io_ptr = handshake_ctx->base.in_end;
        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
        return XTT_RETURN_WANT_READ;
    }

    // 0ii) Ensure we're in the correct state
    if (XTT_SERVER_HANDSHAKE_STATE_PREPARSING_IDCLIENTATTEST != handshake_ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Get message type.
    xtt_msg_type msg_type = *xtt_access_msg_type(handshake_ctx->base.in_message_start);
    if (XTT_ID_CLIENTATTEST_MSG != msg_type
            && XTT_SESSION_CLIENTATTEST_NOPAYLOAD_MSG != msg_type
            && XTT_SESSION_CLIENTATTEST_PAYLOAD_MSG != msg_type) {
        rc = XTT_RETURN_INCORRECT_TYPE;
        goto finish;
    }

    // 2) Check the length of the ClientAttest message.
    uint16_t clientattest_length;
    bigendian_to_short(xtt_access_length(handshake_ctx->base.in_message_start),
                       &clientattest_length);
    uint16_t minimum_length = sizeof(xtt_msg_type_raw)
        + sizeof(xtt_length)
        + sizeof(xtt_version_raw)
        + sizeof(xtt_suite_spec_raw);
    if (clientattest_length < minimum_length) {
        rc = XTT_RETURN_INCORRECT_LENGTH;
        goto finish;
    }
    xtt_version_raw claimed_version = *xtt_access_version(handshake_ctx->base.in_message_start);
    xtt_suite_spec claimed_suite_spec;
    xtt_suite_spec_raw claimed_suite_spec_raw;
    bigendian_to_short(xtt_identityclientattest_access_suite_spec(handshake_ctx->base.in_message_start,
                                                                  claimed_version),
                       &claimed_suite_spec_raw);
    claimed_suite_spec = claimed_suite_spec_raw;
    if (clientattest_length != xtt_identityclientattest_total_length(claimed_version, claimed_suite_spec)) {
        rc = XTT_RETURN_INCORRECT_LENGTH;
        goto finish;
    }

    // 3) Check client's version and suite_spec
    if (claimed_version != handshake_ctx->base.version) {
        rc = XTT_RETURN_UNKNOWN_VERSION;
        goto finish;
    }

    if (claimed_suite_spec != handshake_ctx->base.suite_spec) {
        rc = XTT_RETURN_UNKNOWN_SUITE_SPEC;
        goto finish;
    }

    // 4) Check that client's echoed server_cookie is the one we sent.
    // TODO: We probably don't need to do this, the signature will validate the cookie (it's just a nonce)
    rc = validate_server_cookie((xtt_server_cookie*)xtt_identityclientattest_access_servercookie(handshake_ctx->base.in_message_start,
                                                                                                 handshake_ctx->base.version),
                                &handshake_ctx->base,
                                cookie_ctx);
    if (XTT_RETURN_SUCCESS != rc) {
        goto finish;
    }

    // 5) AEAD decrypt the message
    uint16_t decrypted_len;
    assert(sizeof(handshake_ctx->base.clientattest_buffer) >= xtt_identityclientattest_encrypted_part_length(handshake_ctx->base.version,
                                                                                                        handshake_ctx->base.suite_spec));
    rc = handshake_ctx->base.decrypt(handshake_ctx->base.clientattest_buffer,
                                     &decrypted_len,
                                     handshake_ctx->base.in_message_start + xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version),
                                     xtt_identityclientattest_encrypted_part_length(handshake_ctx->base.version,
                                                                                    handshake_ctx->base.suite_spec)
                                           + handshake_ctx->base.mac_length,
                                     handshake_ctx->base.in_message_start,
                                     xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version),
                                     &handshake_ctx->base);
    if (XTT_RETURN_SUCCESS != rc) {
        goto finish;
    }

    // 6) Read-out the claimed longterm_key.
    handshake_ctx->read_longterm_key(handshake_ctx,
                                     NULL,
                                     xtt_encrypted_identityclientattest_access_longtermkey(handshake_ctx->base.clientattest_buffer,
                                                                                           handshake_ctx->base.version));

    // 7) Verify longterm_key_signature
    rc = verify_client_longterm_signature(xtt_encrypted_identityclientattest_access_longtermsignature(handshake_ctx->base.clientattest_buffer,
                                                                                                      handshake_ctx->base.version,
                                                                                                      handshake_ctx->base.suite_spec),
                                          (unsigned char*)&handshake_ctx->base.server_cookie,
                                          handshake_ctx->base.server_signature_buffer,
                                          handshake_ctx->base.in_message_start,
                                          handshake_ctx->base.clientattest_buffer,
                                          certificate_ctx,
                                          handshake_ctx);
    if (XTT_RETURN_SUCCESS != rc) {
        goto finish;
    }

    // 8) Read-out the pseudonym
    handshake_ctx->copy_in_clients_pseudonym(handshake_ctx,
                                             xtt_encrypted_identityclientattest_access_daasignature(handshake_ctx->base.clientattest_buffer,
                                                                                                    handshake_ctx->base.version,
                                                                                                    handshake_ctx->base.suite_spec));

finish:
    if (XTT_RETURN_SUCCESS == rc) {
        // 9) Copy claimed GID.
        memcpy(claimed_group_id_out->data,
               xtt_encrypted_identityclientattest_access_gid(handshake_ctx->base.clientattest_buffer,
                                                             handshake_ctx->base.version,
                                                             handshake_ctx->base.suite_spec),
               sizeof(xtt_group_id));

        // 10) Copy requested ClientID
        memcpy(requested_client_id_out->data,
               xtt_encrypted_identityclientattest_access_id(handshake_ctx->base.clientattest_buffer,
                                                            handshake_ctx->base.version,
                                                            handshake_ctx->base.suite_spec),
               sizeof(xtt_identity_type));

        // 11) Advance state
        handshake_ctx->state = XTT_SERVER_HANDSHAKE_STATE_VERIFYING_GROUPSIGNATURE;

        return XTT_RETURN_WANT_VERIFYGROUPSIGNATURE;
    } else {
        (void)xtt_server_build_error_msg(io_bytes_requested, io_ptr, handshake_ctx);

        *io_ptr = handshake_ctx->base.out_message_start;

        handshake_ctx->state = XTT_SERVER_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
xtt_handshake_server_verify_groupsignature(uint16_t *io_bytes_requested,
                                           unsigned char **io_ptr,
                                           struct xtt_group_public_key_context* group_pub_key_ctx,
                                           const struct xtt_server_certificate_context *certificate_ctx,
                                           struct xtt_server_handshake_context* handshake_ctx)
{
    xtt_return_code_type rc;

    // 0i) Ensure we've read enough
    uint16_t bytes_io_performed_for_this_message = handshake_ctx->base.in_end - handshake_ctx->base.in_message_start;
    uint16_t message_length = xtt_identityclientattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec);
    if (bytes_io_performed_for_this_message < message_length) {
        *io_ptr = handshake_ctx->base.in_end;
        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
        return XTT_RETURN_WANT_READ;
    }

    // 0ii) Ensure we're in the correct state
    if (XTT_SERVER_HANDSHAKE_STATE_VERIFYING_GROUPSIGNATURE != handshake_ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Verify DAA Signature
    rc = verify_daa_signature(xtt_encrypted_identityclientattest_access_daasignature(handshake_ctx->base.clientattest_buffer,
                                                                                     handshake_ctx->base.version,
                                                                                     handshake_ctx->base.suite_spec),
                              (unsigned char*)&handshake_ctx->base.server_cookie,
                              handshake_ctx->base.server_signature_buffer,
                              handshake_ctx->base.in_message_start,
                              handshake_ctx->base.clientattest_buffer,
                              group_pub_key_ctx,
                              certificate_ctx,
                              &handshake_ctx->base);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_RETURN_SUCCESS == rc) {
        // 2) Advance state
        handshake_ctx->state = XTT_SERVER_HANDSHAKE_STATE_BUILDING_IDSERVERFINISHED;

        return XTT_RETURN_WANT_BUILDIDSERVERFINISHED;
    } else {
        (void)xtt_server_build_error_msg(io_bytes_requested, io_ptr, handshake_ctx);

        *io_ptr = handshake_ctx->base.out_message_start;

        handshake_ctx->state = XTT_SERVER_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
xtt_handshake_server_build_idserverfinished(uint16_t *io_bytes_requested,
                                            unsigned char **io_ptr,
                                            const xtt_identity_type *client_id,
                                            struct xtt_server_handshake_context* handshake_ctx)
{
    xtt_return_code_type rc;

    // 0i) Ensure we've read enough
    uint16_t bytes_io_performed_for_this_message = handshake_ctx->base.in_end - handshake_ctx->base.in_message_start;
    uint16_t message_length = xtt_identityclientattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec);
    if (bytes_io_performed_for_this_message < message_length) {
        *io_ptr = handshake_ctx->base.in_end;
        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
        return XTT_RETURN_WANT_READ;
    }

    // 0ii) Ensure we're in the correct state
    if (XTT_SERVER_HANDSHAKE_STATE_BUILDING_IDSERVERFINISHED != handshake_ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Set message type.
    *xtt_access_msg_type(handshake_ctx->base.out_message_start) = XTT_ID_SERVERFINISHED_MSG;

    // 2) Set length.
    short_to_bigendian(xtt_identityserverfinished_total_length(handshake_ctx->base.version,
                                                               handshake_ctx->base.suite_spec),
                       xtt_access_length(handshake_ctx->base.out_message_start));

    // 3) Set version.
    *xtt_access_version(handshake_ctx->base.out_message_start) = handshake_ctx->base.version;

    // 4) Set suite spec.
    short_to_bigendian(handshake_ctx->base.suite_spec,
                       xtt_identityserverfinished_access_suite_spec(handshake_ctx->base.out_message_start, handshake_ctx->base.version));

    // 5) Set the client's id.
    memcpy(xtt_encrypted_identityserverfinished_access_id(handshake_ctx->base.buffer,
                                                          handshake_ctx->base.version),
           client_id->data,
           sizeof(xtt_identity_type));
    // 5i) Also save the client's id to our context
    memcpy(handshake_ctx->clients_identity.data,
           client_id->data,
           sizeof(xtt_identity_type));

    // 6) Set the longterm_key (echo)
    memcpy(xtt_encrypted_identityserverfinished_access_longtermkey(handshake_ctx->base.buffer,
                                                                   handshake_ctx->base.version),
           xtt_encrypted_identityclientattest_access_longtermkey(handshake_ctx->base.clientattest_buffer,
                                                                 handshake_ctx->base.version),
           handshake_ctx->base.longterm_key_length);

    // 7) AEAD encrypt the message
    uint16_t encrypted_len;
    rc = handshake_ctx->base.encrypt(handshake_ctx->base.out_message_start + xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version),
                                     &encrypted_len,
                                     handshake_ctx->base.buffer,
                                     xtt_identityserverfinished_encrypted_part_length(handshake_ctx->base.version,
                                                                                      handshake_ctx->base.suite_spec),
                                     handshake_ctx->base.out_message_start,
                                     xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version),
                                     &handshake_ctx->base);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_RETURN_SUCCESS == rc) {
        // 8) Report ServerFinished message length.
        *io_bytes_requested = xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version)
                        + encrypted_len;
        assert(xtt_identityserverfinished_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec) == *io_bytes_requested);

        // 9) Set io_ptr.
        *io_ptr = handshake_ctx->base.out_message_start;

        // 10) Advance state
        handshake_ctx->state = XTT_SERVER_HANDSHAKE_STATE_SENDING_IDSERVERFINISHED;

        return XTT_RETURN_WANT_WRITE;
    } else {
        (void)xtt_server_build_error_msg(io_bytes_requested, io_ptr, handshake_ctx);

        *io_ptr = handshake_ctx->base.out_message_start;

        handshake_ctx->state = XTT_SERVER_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
xtt_handshake_client_parse_idserverfinished(uint16_t *io_bytes_requested,
                                            unsigned char **io_ptr,
                                            struct xtt_client_handshake_context* handshake_ctx)
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;

    // 0i) Ensure we've read enough
    uint16_t bytes_io_performed_for_this_message = handshake_ctx->base.in_end - handshake_ctx->base.in_message_start;
    uint16_t message_length = xtt_identityserverfinished_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec);
    if (bytes_io_performed_for_this_message < message_length) {
        *io_ptr = handshake_ctx->base.in_end;
        *io_bytes_requested = message_length - bytes_io_performed_for_this_message;
        return XTT_RETURN_WANT_READ;
    }

    // 0ii) Ensure we're in the correct state
    if (XTT_CLIENT_HANDSHAKE_STATE_PARSING_IDSERVERFINISHED != handshake_ctx->state) {
        rc = XTT_RETURN_BAD_HANDSHAKE_ORDER;
        goto finish;
    }

    // 1) Check the length of the ServerFinished message.
    uint16_t serverfinished_length;
    bigendian_to_short(xtt_access_length(handshake_ctx->base.in_message_start), &serverfinished_length);
    uint16_t minimum_length = sizeof(xtt_msg_type_raw)
        + sizeof(xtt_length)
        + sizeof(xtt_version_raw)
        + sizeof(xtt_suite_spec_raw);
    if (serverfinished_length < minimum_length) {
        rc = XTT_RETURN_INCORRECT_LENGTH;
        goto finish;
    }
    xtt_version_raw claimed_version = *xtt_access_version(handshake_ctx->base.in_message_start);
    xtt_suite_spec claimed_suite_spec;
    xtt_suite_spec_raw claimed_suite_spec_raw;
    bigendian_to_short(xtt_identityserverfinished_access_suite_spec(handshake_ctx->base.in_message_start,
                                                                    claimed_version),
                       &claimed_suite_spec_raw);
    claimed_suite_spec = claimed_suite_spec_raw;
    if (serverfinished_length != xtt_identityserverfinished_total_length(claimed_version, claimed_suite_spec)) {
        rc = XTT_RETURN_INCORRECT_LENGTH;
        goto finish;
    }

    // 2) Check message type.
    if (XTT_ID_SERVERFINISHED_MSG != *xtt_access_msg_type(handshake_ctx->base.in_message_start)) {
        rc = XTT_RETURN_INCORRECT_TYPE;
        goto finish;
    }

    // 3) Check server's version and suite_spec
    if (claimed_version != handshake_ctx->base.version) {
        rc = XTT_RETURN_UNKNOWN_VERSION;
        goto finish;
    }

    if (claimed_suite_spec != handshake_ctx->base.suite_spec) {
        rc = XTT_RETURN_UNKNOWN_SUITE_SPEC;
        goto finish;
    }

    // 4) AEAD decrypt the message
    uint16_t decrypted_len;
    assert(sizeof(handshake_ctx->base.buffer) >= xtt_identityserverfinished_encrypted_part_length(handshake_ctx->base.version,
                                                                                             handshake_ctx->base.suite_spec));

    rc = handshake_ctx->base.decrypt(handshake_ctx->base.buffer,
                                     &decrypted_len,
                                     handshake_ctx->base.in_message_start + xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version),
                                     xtt_identityserverfinished_encrypted_part_length(handshake_ctx->base.version,
                                                                                      handshake_ctx->base.suite_spec)
                                           + handshake_ctx->base.mac_length,
                                     handshake_ctx->base.in_message_start,
                                     xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version),
                                     &handshake_ctx->base);
    if (XTT_RETURN_SUCCESS != rc)
        goto finish;

    // 5) Get the client_id sent by the server (and make sure it matches ours, if we requested one).
    if (0 == xtt_crypto_memcmp(xtt_null_identity.data, handshake_ctx->identity.data, sizeof(xtt_identity_type))) {
        memcpy(handshake_ctx->identity.data,
               xtt_encrypted_identityserverfinished_access_id(handshake_ctx->base.buffer, handshake_ctx->base.version),
               sizeof(xtt_identity_type));
    } else if (0 != xtt_crypto_memcmp(handshake_ctx->identity.data,
                                      xtt_encrypted_identityserverfinished_access_id(handshake_ctx->base.buffer, handshake_ctx->base.version),
                                      sizeof(xtt_identity_type))) {
        rc = XTT_RETURN_BAD_FINISH;
        goto finish;
    }

    if (0 != handshake_ctx->compare_longterm_keys(xtt_encrypted_identityserverfinished_access_longtermkey(handshake_ctx->base.buffer, handshake_ctx->base.version),
                                                  handshake_ctx)) {
        rc = XTT_RETURN_BAD_FINISH;
        goto finish;
    }
finish:
    if (XTT_RETURN_SUCCESS == rc) {
        // 6) Advance the state
        handshake_ctx->state = XTT_CLIENT_HANDSHAKE_STATE_FINISHED;

        return XTT_RETURN_HANDSHAKE_FINISHED;
    } else {
        (void)xtt_client_build_error_msg(io_bytes_requested, io_ptr, handshake_ctx);

        // 13) Set io_ptr
        *io_ptr = handshake_ctx->base.out_message_start;

        handshake_ctx->state = XTT_CLIENT_HANDSHAKE_STATE_ERROR;

        return rc;
    }
}

xtt_return_code_type
parse_message_header(uint16_t *length_out,
                     struct xtt_handshake_context *ctx)
{
    xtt_msg_type msg_type = *xtt_access_msg_type(ctx->in_message_start);
    switch (msg_type) {
        case XTT_CLIENTINIT_MSG:
        case XTT_SERVERINITANDATTEST_MSG:
        case XTT_ID_CLIENTATTEST_MSG:
        case XTT_ID_SERVERFINISHED_MSG:
        case XTT_SESSION_CLIENTATTEST_NOPAYLOAD_MSG:
        case XTT_SESSION_CLIENTATTEST_PAYLOAD_MSG:
        case XTT_SESSION_SERVERFINISHED_MSG:
        case XTT_RECORD_REGULAR_MSG:
            *length_out = xtt_get_message_length(ctx->in_message_start);

            if (MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH < *length_out && MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH < *length_out ) {
                return XTT_RETURN_INCORRECT_LENGTH;
            }

            return XTT_RETURN_SUCCESS;

        case XTT_ERROR_MSG:
            return XTT_RETURN_RECEIVED_ERROR_MSG;
        default:
            return XTT_RETURN_INCORRECT_TYPE;
    }
}

xtt_return_code_type
parse_client_init(struct xtt_server_handshake_context *ctx_out,
                  const unsigned char* client_init)
{
    // 1) Check the length of the Client Init message.
    uint16_t client_init_length;
    bigendian_to_short(xtt_access_length(client_init), &client_init_length);
    uint16_t minimum_length = sizeof(xtt_msg_type_raw)
        + sizeof(xtt_length)
        + sizeof(xtt_version_raw)
        + sizeof(xtt_suite_spec_raw);
    if (client_init_length < minimum_length)
        return XTT_RETURN_INCORRECT_LENGTH;
    ctx_out->base.version = *xtt_access_version(client_init);
    xtt_suite_spec_raw suite_spec_raw;
    bigendian_to_short(xtt_clientinit_access_suite_spec(client_init,
                                                        ctx_out->base.version),
                       &suite_spec_raw);
    ctx_out->base.suite_spec = suite_spec_raw;
    if (client_init_length != xtt_clientinit_length(ctx_out->base.version, ctx_out->base.suite_spec))
        return XTT_RETURN_INCORRECT_LENGTH;

    // 2) Check message type.
    if (XTT_CLIENTINIT_MSG != *xtt_access_msg_type(client_init))
        return XTT_RETURN_INCORRECT_TYPE;

    xtt_return_code_type rc;

    // 3) Setup our own context from version and suite_spec from client.
    rc = xtt_setup_server_handshake_context(ctx_out,
                                            ctx_out->base.version,
                                            ctx_out->base.suite_spec);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
parse_server_initandattest(struct xtt_client_handshake_context *handshake_ctx,
                           const unsigned char* server_init_and_attest)
{
    // 1) Check the length of the ServerInitAndAttest message.
    uint16_t serverinitandattest_length;
    bigendian_to_short(xtt_access_length(server_init_and_attest),
                       &serverinitandattest_length);
    uint16_t minimum_length = sizeof(xtt_msg_type_raw)
        + sizeof(xtt_length)
        + sizeof(xtt_version_raw)
        + sizeof(xtt_suite_spec_raw);
    if (serverinitandattest_length < minimum_length)
        return XTT_RETURN_INCORRECT_LENGTH;
    xtt_version_raw claimed_version = *xtt_access_version(server_init_and_attest);
    xtt_suite_spec claimed_suite_spec;
    xtt_suite_spec_raw claimed_suite_spec_raw;
    bigendian_to_short(xtt_serverinitandattest_access_suite_spec(server_init_and_attest,
                                                                 claimed_version),
                       &claimed_suite_spec_raw);
    claimed_suite_spec = claimed_suite_spec_raw;
    if (serverinitandattest_length != xtt_serverinitandattest_total_length(claimed_version, claimed_suite_spec))
        return XTT_RETURN_INCORRECT_LENGTH;

    // 2) Check message type.
    if (XTT_SERVERINITANDATTEST_MSG != *xtt_access_msg_type(server_init_and_attest))
        return XTT_RETURN_INCORRECT_TYPE;

    // 3) Check server's version and suite_spec
    if (claimed_version != handshake_ctx->base.version)
        return XTT_RETURN_UNKNOWN_VERSION;

    if (claimed_suite_spec != handshake_ctx->base.suite_spec)
        return XTT_RETURN_UNKNOWN_SUITE_SPEC;

    xtt_return_code_type rc;

    // 4) Run Diffie-Hellman and get handshake AEAD keys.
    rc = derive_handshake_keys(&handshake_ctx->base,
                              handshake_ctx->base.client_init_buffer,
                              server_init_and_attest,
                              xtt_serverinitandattest_access_server_cookie(server_init_and_attest,
                                                                                   handshake_ctx->base.version,
                                                                                   handshake_ctx->base.suite_spec),
                              xtt_serverinitandattest_access_ecdhe_key(server_init_and_attest,
                                                                       handshake_ctx->base.version),
                              1);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    // 5) AEAD decrypt the message
    uint16_t decrypted_len;
    assert(sizeof(handshake_ctx->base.server_initandattest_buffer) >= xtt_serverinitandattest_encrypted_part_length(handshake_ctx->base.version,
                                                                                                               handshake_ctx->base.suite_spec));
    int decrypt_rc = handshake_ctx->base.decrypt(handshake_ctx->base.server_initandattest_buffer,
                                                 &decrypted_len,
                                                 server_init_and_attest + xtt_serverinitandattest_unencrypted_part_length(handshake_ctx->base.version,
                                                                                                                          handshake_ctx->base.suite_spec),
                                                 xtt_serverinitandattest_encrypted_part_length(handshake_ctx->base.version,
                                                                                               handshake_ctx->base.suite_spec)
                                                       + handshake_ctx->base.mac_length,
                                                 server_init_and_attest,
                                                 xtt_serverinitandattest_unencrypted_part_length(handshake_ctx->base.version,
                                                                                                 handshake_ctx->base.suite_spec),
                                                 &handshake_ctx->base);
    if (0 != decrypt_rc)
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_server_build_error_msg(uint16_t *io_bytes_requested,
                           unsigned char **io_ptr,
                           struct xtt_server_handshake_context* handshake_ctx)
{
    *io_ptr = handshake_ctx->base.out_message_start;

    *xtt_access_msg_type(handshake_ctx->base.out_message_start) = XTT_ERROR_MSG;

    short_to_bigendian(xtt_error_msg_length(handshake_ctx->base.version),
                       xtt_access_length(handshake_ctx->base.out_message_start));
    *xtt_access_version(handshake_ctx->base.out_message_start) = handshake_ctx->base.version;

    *io_bytes_requested = xtt_error_msg_length(handshake_ctx->base.version);

    handshake_ctx->state = XTT_SERVER_HANDSHAKE_STATE_ERROR;

    return XTT_RETURN_WANT_WRITE;
}

xtt_return_code_type
xtt_client_build_error_msg(uint16_t *io_bytes_requested,
                           unsigned char **io_ptr,
                           struct xtt_client_handshake_context* handshake_ctx)
{
    *io_ptr = handshake_ctx->base.out_message_start;

    *xtt_access_msg_type(handshake_ctx->base.out_message_start) = XTT_ERROR_MSG;

    short_to_bigendian(xtt_error_msg_length(handshake_ctx->base.version),
                       xtt_access_length(handshake_ctx->base.out_message_start));
    *xtt_access_version(handshake_ctx->base.out_message_start) = handshake_ctx->base.version;

    *io_bytes_requested = xtt_error_msg_length(handshake_ctx->base.version);

    handshake_ctx->state = XTT_CLIENT_HANDSHAKE_STATE_ERROR;

    return XTT_RETURN_WANT_WRITE;
}
