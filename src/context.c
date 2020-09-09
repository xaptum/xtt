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

#include <xtt/context.h>
#include <xtt/crypto_wrapper.h>
#include <xtt/daa_wrapper.h>
#include <xtt/return_codes.h>
#include <xtt/messages.h>

#include "internal/crypto_utils.h"
#include "internal/message_utils.h"
#include "internal/byte_utils.h"

#include <stddef.h>
#include <string.h>
#include <assert.h>

xtt_return_code_type
xtt_initialize_server_handshake_context(struct xtt_server_handshake_context* ctx_out,
                                        unsigned char *in_buffer,
                                        uint16_t in_buffer_size,
                                        unsigned char *out_buffer,
                                        uint16_t out_buffer_size)
{
    if (ctx_out == NULL)
        return XTT_RETURN_NULL_BUFFER;

    if (MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH > in_buffer_size || MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH > out_buffer_size)
        return XTT_RETURN_CONTEXT_BUFFER_OVERFLOW;

    ctx_out->state = XTT_SERVER_HANDSHAKE_STATE_START;

    ctx_out->base.in_buffer_start = in_buffer;
    ctx_out->base.in_message_start = ctx_out->base.in_buffer_start;
    ctx_out->base.in_end = ctx_out->base.in_buffer_start;
    ctx_out->base.out_buffer_start = out_buffer;
    ctx_out->base.out_message_start = ctx_out->base.out_buffer_start;
    ctx_out->base.out_end = ctx_out->base.out_buffer_start;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_setup_server_handshake_context(struct xtt_server_handshake_context* ctx_out,
                                   xtt_version version,
                                   xtt_suite_spec suite_spec)
{
    if (ctx_out == NULL)
        return XTT_RETURN_NULL_BUFFER;

    if (XTT_VERSION_ONE != version)
        return XTT_RETURN_UNKNOWN_VERSION;

    if (XTT_SERVER_HANDSHAKE_STATE_PARSING_CLIENTINIT_AND_BUILDING_SERVERATTEST != ctx_out->state)
        return XTT_RETURN_BAD_HANDSHAKE_ORDER;

    ctx_out->base.version = version;

    ctx_out->base.suite_spec = suite_spec;
    ctx_out->base.suite_ops = xtt_suite_ops_get(suite_spec);
    if (NULL == ctx_out->base.suite_ops)
        return XTT_RETURN_UNKNOWN_SUITE_SPEC;

    xtt_crypto_hmac_init(&ctx_out->base.hash_out, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.inner_hash, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.prf_key, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.handshake_secret, ctx_out->base.suite_ops->hmac);

    xtt_crypto_aead_key_init(&ctx_out->base.rx_key, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_key_init(&ctx_out->base.tx_key, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_nonce_init(&ctx_out->base.rx_iv, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_nonce_init(&ctx_out->base.tx_iv, ctx_out->base.suite_ops->aead);

    ctx_out->base.longterm_key_length = sizeof(xtt_ecdsap256_pub_key);
    ctx_out->base.longterm_key_signature_length = sizeof(xtt_ecdsap256_signature);

    ctx_out->base.tx_sequence_num = 0;
    ctx_out->base.rx_sequence_num = 0;

    ctx_out->read_longterm_key = read_longterm_key_ecdsap256;
    ctx_out->copy_in_clients_pseudonym = copy_in_pseudonym_server_lrsw;
    ctx_out->verify_client_longterm_signature = verify_server_signature_ecdsap256;

    if (0 != ctx_out->base.suite_ops->kx->keypair(&ctx_out->base.kx_pubkey,
                                                  &ctx_out->base.kx_seckey))
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_initialize_client_handshake_context(struct xtt_client_handshake_context* ctx_out,
                                        unsigned char *in_buffer,
                                        uint16_t in_buffer_size,
                                        unsigned char *out_buffer,
                                        uint16_t out_buffer_size,
                                        xtt_version version,
                                        xtt_suite_spec suite_spec)
{
    if (ctx_out == NULL)
        return XTT_RETURN_NULL_BUFFER;

    if (MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH > in_buffer_size || MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH > out_buffer_size)
        return XTT_RETURN_CONTEXT_BUFFER_OVERFLOW;

    if (XTT_VERSION_ONE != version)
        return XTT_RETURN_UNKNOWN_VERSION;

    ctx_out->state = XTT_CLIENT_HANDSHAKE_STATE_START;

    ctx_out->base.version = version;
    ctx_out->base.suite_spec = suite_spec;
    ctx_out->base.suite_ops = xtt_suite_ops_get(suite_spec);
    if (NULL == ctx_out->base.suite_ops)
        return XTT_RETURN_UNKNOWN_SUITE_SPEC;

    ctx_out->base.in_buffer_start = in_buffer;
    ctx_out->base.in_message_start = ctx_out->base.in_buffer_start;
    ctx_out->base.in_end = ctx_out->base.in_buffer_start;
    ctx_out->base.out_buffer_start = out_buffer;
    ctx_out->base.out_message_start = ctx_out->base.out_buffer_start;
    ctx_out->base.out_end = ctx_out->base.out_buffer_start;

    xtt_crypto_hmac_init(&ctx_out->base.hash_out, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.inner_hash, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.prf_key, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.handshake_secret, ctx_out->base.suite_ops->hmac);

    xtt_crypto_aead_key_init(&ctx_out->base.rx_key, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_key_init(&ctx_out->base.tx_key, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_nonce_init(&ctx_out->base.rx_iv, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_nonce_init(&ctx_out->base.tx_iv, ctx_out->base.suite_ops->aead);

    ctx_out->base.longterm_key_length = sizeof(xtt_ecdsap256_pub_key);
    ctx_out->base.longterm_key_signature_length = sizeof(xtt_ecdsap256_signature);

    ctx_out->base.tx_sequence_num = 0;
    ctx_out->base.rx_sequence_num = 0;

    ctx_out->verify_server_signature = verify_server_signature_ecdsap256;

    ctx_out->copy_longterm_key = copy_longterm_key_ecdsap256;

    ctx_out->compare_longterm_keys = compare_longterm_keys_ecdsap256;
    ctx_out->longterm_sign = longterm_sign_ecdsap256;
    ctx_out->copy_in_my_pseudonym = copy_in_pseudonym_client_lrsw;

    if (0 != ctx_out->base.suite_ops->kx->keypair(&ctx_out->base.kx_pubkey,
                                                  &ctx_out->base.kx_seckey))
        return XTT_RETURN_CRYPTO;

    if (0 != xtt_crypto_create_ecdsap256_key_pair(&ctx_out->longterm_key.ecdsap256, &ctx_out->longterm_private_key.ecdsap256))
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}

#ifdef USE_TPM
xtt_return_code_type
xtt_initialize_client_handshake_context_TPM(struct xtt_client_handshake_context* ctx_out,
                                            unsigned char *in_buffer,
                                            uint16_t in_buffer_size,
                                            unsigned char *out_buffer,
                                            uint16_t out_buffer_size,
                                            xtt_version version,
                                            xtt_suite_spec suite_spec,
                                            TPMI_RH_HIERARCHY hierarchy,
                                            const char *hierarchy_password,
                                            size_t hierarchy_password_length,
                                            TPM2_HANDLE parent_handle,
                                            TSS2_TCTI_CONTEXT *tcti_context)
{
    if (ctx_out == NULL)
        return XTT_RETURN_NULL_BUFFER;

    if (MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH > in_buffer_size || MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH > out_buffer_size)
        return XTT_RETURN_CONTEXT_BUFFER_OVERFLOW;

    if (XTT_VERSION_ONE != version)
        return XTT_RETURN_UNKNOWN_VERSION;

    ctx_out->state = XTT_CLIENT_HANDSHAKE_STATE_START;

    ctx_out->base.version = version;
    ctx_out->base.suite_spec = suite_spec;
    ctx_out->base.suite_ops = xtt_suite_ops_get(suite_spec);
    if (NULL == ctx_out->base.suite_ops)
        return XTT_RETURN_UNKNOWN_SUITE_SPEC;

    ctx_out->base.in_buffer_start = in_buffer;
    ctx_out->base.in_message_start = ctx_out->base.in_buffer_start;
    ctx_out->base.in_end = ctx_out->base.in_buffer_start;
    ctx_out->base.out_buffer_start = out_buffer;
    ctx_out->base.out_message_start = ctx_out->base.out_buffer_start;
    ctx_out->base.out_end = ctx_out->base.out_buffer_start;

    xtt_crypto_hmac_init(&ctx_out->base.hash_out, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.inner_hash, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.prf_key, ctx_out->base.suite_ops->hmac);
    xtt_crypto_hmac_init(&ctx_out->base.handshake_secret, ctx_out->base.suite_ops->hmac);

    xtt_crypto_aead_key_init(&ctx_out->base.rx_key, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_key_init(&ctx_out->base.tx_key, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_nonce_init(&ctx_out->base.rx_iv, ctx_out->base.suite_ops->aead);
    xtt_crypto_aead_nonce_init(&ctx_out->base.tx_iv, ctx_out->base.suite_ops->aead);

    ctx_out->base.longterm_key_length = sizeof(xtt_ecdsap256_pub_key);
    ctx_out->base.longterm_key_signature_length = sizeof(xtt_ecdsap256_signature);

    ctx_out->base.tx_sequence_num = 0;
    ctx_out->base.rx_sequence_num = 0;

    ctx_out->verify_server_signature = verify_server_signature_ecdsap256;

    ctx_out->copy_longterm_key = copy_longterm_key_ecdsap256;

    ctx_out->compare_longterm_keys = compare_longterm_keys_ecdsap256;

    ctx_out->hierarchy = hierarchy;

    if (hierarchy_password_length > sizeof(ctx_out->hierarchy_password))
        return XTT_RETURN_BAD_INIT;
    memcpy(ctx_out->hierarchy_password,
           hierarchy_password,
           hierarchy_password_length);
    ctx_out->hierarchy_password_length = hierarchy_password_length;

    ctx_out->parent_handle = parent_handle;

    ctx_out->tcti_context = tcti_context;

    ctx_out->longterm_sign = longterm_sign_ecdsap256TPM;

    ctx_out->copy_in_my_pseudonym = copy_in_pseudonym_client_lrsw;

    if (0 != ctx_out->base.suite_ops->kx->keypair(&ctx_out->base.kx_pubkey,
                                                  &ctx_out->base.kx_seckey))
        return XTT_RETURN_CRYPTO;

    if (TSS2_RC_SUCCESS != xtpm_gen_key(ctx_out->tcti_context,
                                        ctx_out->parent_handle,
                                        ctx_out->hierarchy,
                                        ctx_out->hierarchy_password,
                                        ctx_out->hierarchy_password_length,
                                        &ctx_out->longterm_private_key_tpm))
        return XTT_RETURN_CRYPTO;

    if (TSS2_RC_SUCCESS != xtpm_get_public_key(&ctx_out->longterm_private_key_tpm,
                                               ctx_out->longterm_key.ecdsap256.data))
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}
#endif

xtt_return_code_type
xtt_initialize_server_cookie_context(struct xtt_server_cookie_context* ctx)
{
    // We're not currently using anything in the cookie context, so NOOP.
    (void)ctx;
    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_initialize_server_certificate_context_ecdsap256(struct xtt_server_certificate_context *ctx_out,
                                                  const unsigned char *serialized_certificate,
                                                  const xtt_ecdsap256_priv_key *private_key)
{
    ctx_out->sign = sign_server_ecdsap256;

    ctx_out->signature_length = sizeof(xtt_ecdsap256_signature);

    ctx_out->private_key.ecdsap256 = *private_key;

    ctx_out->serialized_certificate = (struct xtt_server_certificate_raw_type*)ctx_out->serialized_certificate_raw;
    memcpy(ctx_out->serialized_certificate_raw,
           serialized_certificate,
           xtt_server_certificate_length_fromsignaturetype(XTT_SERVER_SIGNATURE_TYPE_ECDSAP256));

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_initialize_server_root_certificate_context_ecdsap256(struct xtt_server_root_certificate_context *cert_out,
                                                       xtt_certificate_root_id *id,
                                                       xtt_ecdsap256_pub_key *public_key)
{
    cert_out->verify_signature = verify_root_ecdsap256;

    cert_out->type = XTT_SERVER_SIGNATURE_TYPE_ECDSAP256;

    cert_out->id = *id;

    cert_out->public_key.ecdsap256 = *public_key;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_initialize_group_public_key_context_lrsw(struct xtt_group_public_key_context *ctx_out,
                                                 const unsigned char *basename,
                                                 uint16_t basename_length,
                                                 const xtt_daa_group_pub_key_lrsw *gpk)
{
    ctx_out->verify_signature = verify_lrsw;

    ctx_out->gpk.lrsw = *gpk;

    if (basename_length > sizeof(ctx_out->basename))
        return XTT_RETURN_BAD_INIT;
    memcpy(ctx_out->basename,
           basename,
           basename_length);
    ctx_out->basename_length = basename_length;

    return XTT_RETURN_SUCCESS;
}

#ifdef USE_TPM
xtt_return_code_type
xtt_initialize_client_group_context_lrswTPM(struct xtt_client_group_context *ctx_out,
                                            xtt_group_id *gid,
                                            xtt_daa_credential_lrsw *cred,
                                            const unsigned char *basename,
                                            uint16_t basename_length,
                                            TPM_HANDLE key_handle,
                                            const char *key_password,
                                            uint16_t key_password_length,
                                            TSS2_TCTI_CONTEXT *tcti_context)
{
    ctx_out->sign = sign_lrswTPM;

    ctx_out->gid = *gid;

    ctx_out->cred.lrsw = *cred;

    if (basename_length > sizeof(ctx_out->basename))
        return XTT_RETURN_BAD_INIT;
    memcpy(ctx_out->basename,
           basename,
           basename_length);
    ctx_out->basename_length = basename_length;

    ctx_out->key_handle = key_handle;

    if (key_password_length > sizeof(ctx_out->key_password))
        return XTT_RETURN_BAD_INIT;
    memcpy(ctx_out->key_password,
           key_password,
           key_password_length);
    ctx_out->key_password_length = key_password_length;

    ctx_out->tcti_context = tcti_context;

    return XTT_RETURN_SUCCESS;
}
#endif

xtt_return_code_type
xtt_initialize_client_group_context_lrsw(struct xtt_client_group_context *ctx_out,
                                xtt_group_id *gid,
                                xtt_daa_priv_key_lrsw *priv_key,
                                xtt_daa_credential_lrsw *cred,
                                const unsigned char *basename,
                                uint16_t basename_length)
{
    ctx_out->sign = sign_lrsw;

    ctx_out->gid = *gid;

    ctx_out->priv_key.lrsw = *priv_key;

    ctx_out->cred.lrsw = *cred;

    if (basename_length > sizeof(ctx_out->basename))
        return XTT_RETURN_BAD_INIT;
    memcpy(ctx_out->basename,
           basename,
           basename_length);
    ctx_out->basename_length = basename_length;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_get_version(xtt_version *version_out,
                const struct xtt_server_handshake_context *handshake_context)
{
    // TODO: Check state
    switch (handshake_context->base.version) {
        case XTT_VERSION_ONE:
            *version_out = handshake_context->base.version;
            return XTT_RETURN_SUCCESS;
        default:
            return XTT_RETURN_UNKNOWN_VERSION;
    }

}

xtt_return_code_type
xtt_get_suite_spec(xtt_suite_spec *suite_spec_out,
                   const struct xtt_server_handshake_context *handshake_context)
{
    // TODO: Check state
    switch (handshake_context->base.suite_spec) {
        case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
        case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
        case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
        case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
            *suite_spec_out = handshake_context->base.suite_spec;
            return XTT_RETURN_SUCCESS;
        default:
            return XTT_RETURN_UNKNOWN_SUITE_SPEC;
    }
}

xtt_return_code_type
xtt_get_clients_longterm_key_ecdsap256(xtt_ecdsap256_pub_key *longterm_key_out,
                                     const struct xtt_server_handshake_context *handshake_context)
{
    // TODO: Check state
    memcpy(longterm_key_out,
           handshake_context->clients_longterm_key.ecdsap256.data,
           sizeof(xtt_ecdsap256_pub_key));

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_get_clients_identity(xtt_identity_type *client_id_out,
                          const struct xtt_server_handshake_context *handshake_context)
{
    // TODO: Check state
    memcpy(client_id_out->data,
            handshake_context->clients_identity.data,
            sizeof(xtt_identity_type));

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_get_clients_pseudonym_lrsw(xtt_daa_pseudonym_lrsw *pseudonym_out,
                               const struct xtt_server_handshake_context *handshake_context)
{
    // TODO: Check state
    memcpy(pseudonym_out->data,
           handshake_context->clients_pseudonym.lrsw.data,
           sizeof(xtt_daa_pseudonym_lrsw));

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_get_my_longterm_key_ecdsap256(xtt_ecdsap256_pub_key *longterm_key_out,
                                const struct xtt_client_handshake_context *handshake_context)
{
    // TODO: Check state
    memcpy(longterm_key_out->data,
           handshake_context->longterm_key.ecdsap256.data,
           sizeof(xtt_ecdsap256_pub_key));

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_get_my_longterm_private_key_ecdsap256(xtt_ecdsap256_priv_key *longterm_key_priv_out,
                                        const struct xtt_client_handshake_context *handshake_context)
{
    // TODO: Check state
    memcpy(longterm_key_priv_out->data,
           handshake_context->longterm_private_key.ecdsap256.data,
           sizeof(xtt_ecdsap256_priv_key));

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_get_my_identity(xtt_identity_type *id_out,
                     const struct xtt_client_handshake_context *handshake_context)
{
    // TODO: Check state
    memcpy(id_out->data,
            handshake_context->identity.data,
            sizeof(xtt_identity_type));

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
xtt_get_my_pseudonym_lrsw(xtt_daa_pseudonym_lrsw *pseudonym_out,
                          const struct xtt_client_handshake_context *handshake_context)
{
    // TODO: Check state
    memcpy(pseudonym_out->data,
           handshake_context->pseudonym.lrsw.data,
           sizeof(xtt_daa_pseudonym_lrsw));

    return XTT_RETURN_SUCCESS;
}
