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

#include "server_cookie.h"
#include "message_utils.h"

#include <xtt/crypto_wrapper.h>

xtt_return_code_type
build_server_cookie(xtt_server_cookie *cookie,
                    struct xtt_handshake_context *handshake_ctx,
                    struct xtt_server_cookie_context *cookie_ctx)
{
    (void)cookie_ctx;

    // For now, just generate a random nonce,
    // and don't support the 'no-local-state' option.
    xtt_crypto_get_random(cookie->data,
                         sizeof(xtt_server_cookie)); 

    // Save cookie to context
    handshake_ctx->server_cookie = *cookie;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
validate_server_cookie(xtt_server_cookie *cookie,
                       struct xtt_handshake_context *handshake_ctx,
                       struct xtt_server_cookie_context *cookie_ctx)
{
    (void)cookie_ctx;
    // In the future, check that version and suite_spec are the same as before,
    // and that the cookie decrypts using one of the cookie_ctx keys and hasn't been seen before.

    // For now, just ensure that this is the same cookie as the one we sent.
    return xtt_crypto_memcmp(cookie->data,
                            handshake_ctx->server_cookie.data,
                            sizeof(xtt_server_cookie));
}
