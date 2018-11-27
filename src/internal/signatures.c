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

#include "signatures.h"
#include "message_utils.h"
#include "byte_utils.h"

#include <xtt/crypto_wrapper.h>
#include <xtt/certificates.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

static
xtt_return_code_type
generate_server_sig_hash(unsigned char *hash_out,
                         const unsigned char *client_init,
                         const unsigned char *server_initandattest_unencrypted_part,
                         const unsigned char *server_initandattest_encryptedpart_uptosignature,
                         struct xtt_handshake_context *handshake_ctx);

static
xtt_return_code_type
generate_client_sig_hash(unsigned char *hash_out,
                         const unsigned char *server_cookie,
                         const struct xtt_server_certificate_raw_type *certificate,
                         const unsigned char *server_signature,
                         const unsigned char *identityclientattest_unencrypted_part,
                         const unsigned char *identityclientattest_encryptedpart_uptosignature,
                         int is_daa,
                         struct xtt_handshake_context *handshake_ctx);


xtt_return_code_type
generate_server_signature(unsigned char* signature_out,
                          const unsigned char *client_init,
                          const unsigned char *server_initandattest_unencrypted_part,
                          const unsigned char *server_initandattest_encryptedpart_uptosignature,
                          struct xtt_handshake_context *handshake_ctx,
                          const struct xtt_server_certificate_context *certificate_ctx)
{
    xtt_return_code_type rc;

    rc = generate_server_sig_hash(handshake_ctx->hash_out_buffer,
                                  client_init,
                                  server_initandattest_unencrypted_part,
                                  server_initandattest_encryptedpart_uptosignature,
                                  handshake_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    rc = certificate_ctx->sign(signature_out,
                               handshake_ctx->hash_out_buffer,
                               handshake_ctx->hash_length,
                               certificate_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
generate_daa_signature(unsigned char *signature_out,
                       const unsigned char *server_cookie,
                       const struct xtt_server_certificate_raw_type *certificate,
                       const unsigned char *server_signature,
                       const unsigned char *identityclientattest_unencrypted_part,
                       const unsigned char *identityclientattest_encryptedpart_uptosignature,
                       struct xtt_handshake_context *handshake_ctx,
                       struct xtt_client_group_context *group_ctx)
{
    xtt_return_code_type rc;

    rc = generate_client_sig_hash(handshake_ctx->hash_out_buffer,
                                  server_cookie,
                                  certificate,
                                  server_signature,
                                  identityclientattest_unencrypted_part,
                                  identityclientattest_encryptedpart_uptosignature,
                                  1,
                                  handshake_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    rc = group_ctx->sign(signature_out,
                       handshake_ctx->hash_out_buffer,
                       handshake_ctx->hash_length,
                       group_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
verify_daa_signature(unsigned char *signature,
                     const unsigned char *server_cookie,
                     const unsigned char *server_signature,
                     const unsigned char *identityclientattest_unencrypted_part,
                     const unsigned char *identityclientattest_encryptedpart_uptosignature,
                     struct xtt_group_public_key_context* group_pub_key_ctx,
                     const struct xtt_server_certificate_context *server_certificate_ctx,
                     struct xtt_handshake_context *handshake_ctx)
{
    xtt_return_code_type rc;

    rc = generate_client_sig_hash(handshake_ctx->hash_out_buffer,
                                  server_cookie,
                                  server_certificate_ctx->serialized_certificate,
                                  server_signature,
                                  identityclientattest_unencrypted_part,
                                  identityclientattest_encryptedpart_uptosignature,
                                  1,
                                  handshake_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    rc = group_pub_key_ctx->verify_signature(signature,
                                                 handshake_ctx->hash_out_buffer,
                                                 handshake_ctx->hash_length,
                                                 group_pub_key_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
generate_client_longterm_signature(unsigned char *signature_out,
                                   const unsigned char *server_cookie,
                                   const struct xtt_server_certificate_raw_type *certificate,
                                   const unsigned char *server_signature,
                                   const unsigned char *identityclientattest_unencrypted_part,
                                   const unsigned char *identityclientattest_encryptedpart_uptosignature,
                                   struct xtt_client_handshake_context *handshake_ctx)
{
    xtt_return_code_type rc;

    rc = generate_client_sig_hash(handshake_ctx->base.hash_out_buffer,
                                  server_cookie,
                                  certificate,
                                  server_signature,
                                  identityclientattest_unencrypted_part,
                                  identityclientattest_encryptedpart_uptosignature,
                                  0,
                                  &handshake_ctx->base);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    rc = handshake_ctx->longterm_sign(signature_out,
                                      handshake_ctx->base.hash_out_buffer,
                                      handshake_ctx->base.hash_length,
                                      handshake_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
verify_client_longterm_signature(unsigned char *signature,
                                 const unsigned char *server_cookie,
                                 const unsigned char *server_signature,
                                 const unsigned char *identityclientattest_unencrypted_part,
                                 const unsigned char *identityclientattest_encryptedpart_uptosignature,
                                 const struct xtt_server_certificate_context *server_certificate_ctx,
                                 struct xtt_server_handshake_context *handshake_ctx)
{
    xtt_return_code_type rc;

    rc = generate_client_sig_hash(handshake_ctx->base.hash_out_buffer,
                                  server_cookie,
                                  server_certificate_ctx->serialized_certificate,
                                  server_signature,
                                  identityclientattest_unencrypted_part,
                                  identityclientattest_encryptedpart_uptosignature,
                                  0,
                                  &handshake_ctx->base);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    unsigned char *client_longterm_key = xtt_encrypted_identityclientattest_access_longtermkey(identityclientattest_encryptedpart_uptosignature,
                                                                                               handshake_ctx->base.version);
    rc = handshake_ctx->verify_client_longterm_signature(signature,
                                                         handshake_ctx->base.hash_out_buffer,
                                                         handshake_ctx->base.hash_length,
                                                         client_longterm_key);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
verify_server_signature(const unsigned char *signature,
                        const struct xtt_server_root_certificate_context* root_server_certificate,
                        const unsigned char *client_init,
                        const unsigned char *server_initandattest_unencrypted_part,
                        const unsigned char *server_initandattest_encryptedpart_uptosignature,
                        struct xtt_client_handshake_context *handshake_ctx)
{
    xtt_return_code_type rc;

    // 1) Check that our root cert does in fact have the id claimed by the server cert.
    xtt_certificate_root_id *claimed_root
        = (xtt_certificate_root_id*)xtt_server_certificate_access_rootid(xtt_encrypted_serverinitandattest_access_certificate(server_initandattest_encryptedpart_uptosignature,
                                                                                                  handshake_ctx->base.version));

    if (0 != xtt_crypto_memcmp(root_server_certificate->id.data, claimed_root->data, sizeof(xtt_certificate_root_id)))
        return XTT_RETURN_BAD_CERTIFICATE;

    // 2) Check that the root signature in the server cert verifies using that root cert.
    struct xtt_server_certificate_raw_type *certificate = xtt_encrypted_serverinitandattest_access_certificate(server_initandattest_encryptedpart_uptosignature,
                                                                                                           handshake_ctx->base.version);
    rc = root_server_certificate->verify_signature(xtt_server_certificate_access_rootsignature(certificate, handshake_ctx->base.suite_spec),
                                                                                               certificate,
                                                                                               root_server_certificate);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;
    // 3) Check that the server signature verifies using the server cert.
    rc = generate_server_sig_hash(handshake_ctx->base.hash_out_buffer,
                                  client_init,
                                  server_initandattest_unencrypted_part,
                                  server_initandattest_encryptedpart_uptosignature,
                                  &handshake_ctx->base);
    if (XTT_RETURN_SUCCESS != rc)
        return rc;
    rc = handshake_ctx->verify_server_signature(signature,
                                                handshake_ctx->base.hash_out_buffer,
                                                handshake_ctx->base.hash_length,
                                                xtt_server_certificate_access_pubkey(xtt_encrypted_serverinitandattest_access_certificate(server_initandattest_encryptedpart_uptosignature,
                                                                                                            handshake_ctx->base.version)));
    if (XTT_RETURN_SUCCESS != rc)
        return rc;

    return XTT_RETURN_SUCCESS;
}

xtt_return_code_type
generate_server_sig_hash(unsigned char *hash_out,
                         const unsigned char *client_init,
                         const unsigned char *server_initandattest_unencrypted_part,
                         const unsigned char *server_initandattest_encryptedpart_uptosignature,
                         struct xtt_handshake_context *handshake_ctx)
{
    uint16_t client_init_length = xtt_clientinit_length(handshake_ctx->version, handshake_ctx->suite_spec);
    uint16_t server_initandattest_up_to_signature_length = xtt_serverinitandattest_uptosignature_length(handshake_ctx->version,
                                                                                                       handshake_ctx->suite_spec);

    // 1) Create inner hash: hash_ext(ClientInit || ServerInitAndAttest-up-to-signature)
    uint16_t inner_hash_input_length = client_init_length + server_initandattest_up_to_signature_length;
    assert(sizeof(handshake_ctx->hash_buffer) >= sizeof(inner_hash_input_length) + inner_hash_input_length);

    unsigned char *hash_input = handshake_ctx->hash_buffer;

    // 1i) Copy in the inner hash length to the hash input buffer.
    short_to_bigendian(inner_hash_input_length, hash_input);
    hash_input += sizeof(inner_hash_input_length);

    // 1ii) Copy in the ClientInit to the hash input buffer.
    memcpy(hash_input, client_init, client_init_length);
    hash_input += client_init_length;

    // 1iii) Copy in the ServerInitAndAttest unencrypted part to the hash input buffer.
    memcpy(hash_input,
           server_initandattest_unencrypted_part,
           xtt_serverinitandattest_unencrypted_part_length(handshake_ctx->version,
                                                          handshake_ctx->suite_spec));
    hash_input += xtt_serverinitandattest_unencrypted_part_length(handshake_ctx->version,
                                                                 handshake_ctx->suite_spec);

    // 1iv) Copy in the ServerInitAndAttest encrypted-part-up-to-signature to the hash input buffer.
    memcpy(hash_input,
           server_initandattest_encryptedpart_uptosignature,
           xtt_serverinitandattest_encrypted_part_uptosignature_length(handshake_ctx->version,
                                                                      handshake_ctx->suite_spec));
    hash_input += xtt_serverinitandattest_encrypted_part_uptosignature_length(handshake_ctx->version,
                                                                             handshake_ctx->suite_spec);

    // 1v) Hash the hash input buffer to get the inner hash.
    uint16_t inner_hash_length;
    int hash_ret = handshake_ctx->hash(hash_out,
                                            &inner_hash_length,
                                            handshake_ctx->hash_buffer,
                                            inner_hash_input_length + sizeof(inner_hash_input_length));
    if (0 != hash_ret)
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}

static
xtt_return_code_type
generate_client_sig_hash(unsigned char *hash_out,
                         const unsigned char *server_cookie,
                         const struct xtt_server_certificate_raw_type *certificate,
                         const unsigned char *server_signature,
                         const unsigned char *identityclientattest_unencrypted_part,
                         const unsigned char *identityclientattest_encryptedpart_uptosignature,
                         int is_daa,
                         struct xtt_handshake_context *handshake_ctx)
{
    // ClientSigHash = hash_ext(inner-hash || server_cookie || certificate || signature_s || Identity_ClientAttest-up-to-sig)
    //      inner-hash = 'inner-hash' from HandshakeKeyHash (saved during HandshakeKeyHash generation)

    uint16_t outer_hash_input_length = handshake_ctx->hash_length
                                            + sizeof(*server_cookie)
                                            + xtt_identityclientattest_uptofirstsignature_length(handshake_ctx->version,
                                                                                                 handshake_ctx->suite_spec);
    if (is_daa)
        outer_hash_input_length += handshake_ctx->longterm_key_signature_length;
    assert(sizeof(handshake_ctx->hash_buffer) >= sizeof(outer_hash_input_length) + outer_hash_input_length);

    unsigned char *hash_input = handshake_ctx->hash_buffer;

    // 1) Copy in the outer hash length to the hash input buffer.
    short_to_bigendian(outer_hash_input_length, hash_input);
    hash_input += sizeof(outer_hash_input_length);

    // 2) Copy the inner hash to the hash input buffer.
    memcpy(hash_input, handshake_ctx->inner_hash, handshake_ctx->hash_length);
    hash_input += handshake_ctx->hash_length;

    // 3) Copy the server_cookie to the hash input buffer.
    memcpy(hash_input, server_cookie, sizeof(xtt_server_cookie));
    hash_input += sizeof(*server_cookie);

    // 4) Copy the certificate to the hash input buffer.
    memcpy(hash_input,
           certificate,
           xtt_server_certificate_length(handshake_ctx->suite_spec));
    hash_input += xtt_server_certificate_length(handshake_ctx->suite_spec);

    // 5) Copy the server_signature to the hash input buffer.
    memcpy(hash_input, server_signature, handshake_ctx->longterm_key_signature_length);
    hash_input += handshake_ctx->longterm_key_signature_length;

    // 6) Copy ClientAttest-up-to-signature into the hash input buffer.
    // 6i) Copy the 'unencrypted part'
    memcpy(hash_input,
           identityclientattest_unencrypted_part,
           xtt_identityclientattest_unencrypted_part_length(handshake_ctx->version));
    hash_input += xtt_identityclientattest_unencrypted_part_length(handshake_ctx->version);
    // 6ii) Copy the encrypted-part-up-to-signature
    //      (If a DAA signature, copy the longterm_signature, too)
    uint16_t encrypted_part_to_signature_length = xtt_identityclientattest_encrypted_part_uptofirstsignature_length(handshake_ctx->version,
                                                                                                                    handshake_ctx->suite_spec);
    if (is_daa)
        encrypted_part_to_signature_length += handshake_ctx->longterm_key_signature_length;
    memcpy(hash_input,
           identityclientattest_encryptedpart_uptosignature,
           encrypted_part_to_signature_length);
    hash_input += encrypted_part_to_signature_length;

    // 7) Hash the hash input buffer to get the ClientSigHash.
    uint16_t outer_hash_length;
    int hash_rc = handshake_ctx->hash(hash_out,
                                           &outer_hash_length,
                                           handshake_ctx->hash_buffer,
                                           outer_hash_input_length + sizeof(outer_hash_input_length));
    if (0 != hash_rc)
        return XTT_RETURN_CRYPTO;

    return XTT_RETURN_SUCCESS;
}
