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

#include "key_derivation.h"
#include "message_utils.h"
#include "byte_utils.h"

#include <string.h>
#include <assert.h>

static
xtt_return_code_type
generate_handshake_key_hash(unsigned char *hash_out,
                            struct xtt_handshake_context *handshake_ctx,
                            const unsigned char *client_init,
                            const unsigned char *server_initandattest_uptocookie,
                            const xtt_server_cookie *server_cookie);

xtt_return_code_type
derive_handshake_keys(struct xtt_handshake_context *handshake_ctx,
                      const unsigned char *client_init,
                      const unsigned char *server_initandattest_uptocookie,
                      const xtt_server_cookie *server_cookie,
                      const unsigned char *others_pub_key,
                      int is_client)
{
    xtt_return_code_type rc;

    // 1) Create HandshakeKeyHash.
    rc = generate_handshake_key_hash(handshake_ctx->hash_out_buffer,
                                     handshake_ctx,
                                     client_init,
                                     server_initandattest_uptocookie,
                                     server_cookie);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    // 3) Run Diffie-Hellman
    int dh_rc = handshake_ctx->do_diffie_hellman(handshake_ctx->shared_secret_buffer,
                                                 others_pub_key,
                                                 handshake_ctx);
    if (0 != dh_rc)
        return XTT_RETURN_DIFFIE_HELLMAN;

    // 4) Create handshake_secret: prf_key -> prf<hash_size>(shared_secret)
    int prf_rc = handshake_ctx->prf(handshake_ctx->handshake_secret,
                                    handshake_ctx->hash_length,
                                    handshake_ctx->shared_secret_buffer,
                                    handshake_ctx->shared_secret_length,
                                    handshake_ctx->prf_key,
                                    handshake_ctx->hash_length);
    if (0 != prf_rc)
        return XTT_RETURN_CRYPTO;

    // 5) Create keys and iv's
    memcpy(handshake_ctx->hash_buffer, handshake_ctx->hash_out_buffer, handshake_ctx->hash_length);
    unsigned char *context_cpy = handshake_ctx->hash_buffer + handshake_ctx->hash_length;
    unsigned char *out_ptr;

    // 5i) Create ClientHandshakeKey
    {
        const char *client_handshake_context_string = "XTT handshake client key";
        uint16_t client_handshake_context_string_length = 24;
        assert(strlen(client_handshake_context_string) == client_handshake_context_string_length);
        memcpy(context_cpy, client_handshake_context_string, client_handshake_context_string_length);
        if (is_client) {
            out_ptr = (unsigned char*)&handshake_ctx->tx_key;
        } else {
            out_ptr = (unsigned char*)&handshake_ctx->rx_key;
        }
        prf_rc = handshake_ctx->prf(out_ptr,
                                    handshake_ctx->key_length,
                                    handshake_ctx->hash_buffer,
                                    handshake_ctx->hash_length + client_handshake_context_string_length,
                                    handshake_ctx->handshake_secret,
                                    handshake_ctx->hash_length);
        if (XTT_RETURN_SUCCESS != prf_rc)
            return prf_rc;
    }

    // 5ii) Create ClientHandshakeIV
    {
        const char *client_handshake_context_iv_string = "XTT handshake client iv";
        uint16_t client_handshake_context_iv_string_length = 23;
        assert(strlen(client_handshake_context_iv_string) == client_handshake_context_iv_string_length);
        memcpy(context_cpy, client_handshake_context_iv_string, client_handshake_context_iv_string_length);
        if (is_client) {
            out_ptr = (unsigned char*)&handshake_ctx->tx_iv;
        } else {
            out_ptr = (unsigned char*)&handshake_ctx->rx_iv;
        }
        prf_rc = handshake_ctx->prf(out_ptr,
                                    handshake_ctx->iv_length,
                                    handshake_ctx->hash_buffer,
                                    handshake_ctx->hash_length + client_handshake_context_iv_string_length,
                                    handshake_ctx->handshake_secret,
                                    handshake_ctx->hash_length);
        if (XTT_RETURN_SUCCESS != prf_rc)
            return prf_rc;
    }

    // 5iii) Create ServerHandshakeKey
    {
        const char *server_handshake_context_string = "XTT handshake server key";
        uint16_t server_handshake_context_string_length = 24;
        assert(strlen(server_handshake_context_string) == server_handshake_context_string_length);
        memcpy(context_cpy, server_handshake_context_string, server_handshake_context_string_length);
        if (is_client) {
            out_ptr = (unsigned char*)&handshake_ctx->rx_key;
        } else {
            out_ptr = (unsigned char*)&handshake_ctx->tx_key;
        }
        prf_rc = handshake_ctx->prf(out_ptr,
                                    handshake_ctx->key_length,
                                    handshake_ctx->hash_buffer,
                                    handshake_ctx->hash_length + server_handshake_context_string_length,
                                    handshake_ctx->handshake_secret,
                                    handshake_ctx->hash_length);

        if (XTT_RETURN_SUCCESS != prf_rc)
            return prf_rc;
    }

    // 5ii) Create ServerHandshakeIV
    {
        const char *server_handshake_context_iv_string = "XTT handshake server iv";
        uint16_t server_handshake_context_iv_string_length = 23;
        assert(strlen(server_handshake_context_iv_string) == server_handshake_context_iv_string_length);
        memcpy(context_cpy, server_handshake_context_iv_string, server_handshake_context_iv_string_length);
        if (is_client) {
            out_ptr = (unsigned char*)&handshake_ctx->rx_iv;
        } else {
            out_ptr = (unsigned char*)&handshake_ctx->tx_iv;
        }
        prf_rc = handshake_ctx->prf(out_ptr,
                                    handshake_ctx->iv_length,
                                    handshake_ctx->hash_buffer,
                                    handshake_ctx->hash_length + server_handshake_context_iv_string_length,
                                    handshake_ctx->handshake_secret,
                                    handshake_ctx->hash_length);
        if (XTT_RETURN_SUCCESS != prf_rc)
            return prf_rc;
    }

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
generate_handshake_key_hash(unsigned char *hash_out,
                            struct xtt_handshake_context *handshake_ctx,
                            const unsigned char *client_init,
                            const unsigned char *server_initandattest_uptocookie,
                            const xtt_server_cookie *server_cookie)
{
    uint16_t client_init_length = xtt_clientinit_length(handshake_ctx->version, handshake_ctx->suite_spec);
    uint16_t server_initandattest_up_to_cookie_length = xtt_serverinitandattest_uptocookie_length(handshake_ctx->version,
                                                                                                 handshake_ctx->suite_spec);

    // 1) Create inner hash: hash_ext(ClientInit || ServerInitAndAttest-up-to-cookie)
    uint16_t inner_hash_input_length = client_init_length + server_initandattest_up_to_cookie_length;
    assert(sizeof(handshake_ctx->hash_buffer) >= sizeof(inner_hash_input_length) + inner_hash_input_length);

    unsigned char *hash_input = handshake_ctx->hash_buffer;

    // 1i) Copy in the inner hash length to the hash input buffer.
    short_to_bigendian(inner_hash_input_length, hash_input);
    hash_input += sizeof(inner_hash_input_length);

    // 1ii) Copy in the ClientInit to the hash input buffer.
    memcpy(hash_input, client_init, client_init_length);
    hash_input += client_init_length;

    // 1iii) Copy in the ServerInitAndAttest-up-to-cookie to the hash input buffer.
    memcpy(hash_input,
           server_initandattest_uptocookie,
           server_initandattest_up_to_cookie_length);
    hash_input += server_initandattest_up_to_cookie_length;
                                                                                            
    // 1iv) Hash the hash input buffer to get the inner hash.
    //      (and save that inner hash to our handshake_ctx, for later use).
    uint16_t inner_hash_length;
    int hash_rc = handshake_ctx->hash(handshake_ctx->inner_hash,
                                      &inner_hash_length,
                                      handshake_ctx->hash_buffer,
                                      inner_hash_input_length + sizeof(inner_hash_input_length));
    if (0 != hash_rc)
        return XTT_RETURN_CRYPTO;

    // 2) Create HandshakeKeyHash: hash_ext(inner-hash || server_cookie)
    uint16_t outer_hash_input_length = inner_hash_length + sizeof(xtt_server_cookie);
    assert(sizeof(handshake_ctx->hash_buffer) >= sizeof(outer_hash_input_length) + outer_hash_input_length);

    hash_input = handshake_ctx->hash_buffer;

    // 2i) Copy in the outer hash length to the hash input buffer.
    short_to_bigendian(outer_hash_input_length, hash_input);
    hash_input += sizeof(outer_hash_input_length);

    // 2ii) Copy the inner hash to the hash input buffer.
    memcpy(hash_input, handshake_ctx->inner_hash, handshake_ctx->hash_length);
    hash_input += handshake_ctx->hash_length;

    // 2iii) Copy the server_cookie to the hash input buffer.
    memcpy(hash_input, server_cookie, sizeof(xtt_server_cookie));
    hash_input += sizeof(xtt_server_cookie);

    // 2iv) Hash the hash input buffer to get the HandshakeKeyHash.
    uint16_t outer_hash_length;
    hash_rc = handshake_ctx->hash(hash_out,
                                  &outer_hash_length,
                                  handshake_ctx->hash_buffer,
                                  outer_hash_input_length + sizeof(outer_hash_input_length));
    if (0 != hash_rc)
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}
