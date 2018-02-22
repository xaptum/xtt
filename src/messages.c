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

#include "internal/message_utils.h"
#include "internal/byte_utils.h"
#include "internal/server_cookie.h"
#include "internal/signatures.h"
#include "internal/key_derivation.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

static
xtt_error_code
parse_client_init(struct xtt_server_handshake_context *ctx_out,
                  const unsigned char* client_init);

static
xtt_error_code
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

xtt_error_code
xtt_build_client_init(unsigned char* out_buffer,
                      uint16_t* out_length,
                      struct xtt_client_handshake_context* ctx)
{
    // 1) Set message type.
    *xtt_access_msg_type(out_buffer) = XTT_CLIENTINIT_MSG;

    // 2) Set length.
    short_to_bigendian(xtt_clientinit_length(ctx->base.version, ctx->base.suite_spec),
                       xtt_access_length(out_buffer));

    // 3) Set version.
    *xtt_access_version(out_buffer) = ctx->base.version;

    // 4) Set suite spec.
    short_to_bigendian(ctx->base.suite_spec,
                       xtt_clientinit_access_suite_spec(out_buffer, ctx->base.version));

    // 5) Generate nonce.
    xtt_crypto_get_random(xtt_clientinit_access_nonce(out_buffer, ctx->base.version)->data,
                         sizeof(xtt_signing_nonce)); 

    // 6) Set Diffie-Hellman key pair.
    // Key pair is assumed to have been generated previously
    // by a call to the init function for the handshake context.
    ctx->base.copy_dh_pubkey(xtt_clientinit_access_ecdhe_key(out_buffer,
                                                             ctx->base.version),
                             NULL,
                             &ctx->base);

    // 7) Report ClientInit message length.
    *out_length = xtt_clientinit_length(ctx->base.version, ctx->base.suite_spec);

    // 8) Copy ClientInit message for later parsing of response.
    assert(sizeof(ctx->base.client_init_buffer) >= *out_length);
    memcpy(ctx->base.client_init_buffer, out_buffer, *out_length);

    return XTT_ERROR_SUCCESS;
}

xtt_error_code
xtt_build_server_init_and_attest(unsigned char* out_buffer,
                                 uint16_t* out_length,
                                 struct xtt_server_handshake_context* ctx_out,
                                 const unsigned char* client_init,
                                 const struct xtt_server_certificate_context* certificate_ctx,
                                 struct xtt_server_cookie_context* cookie_ctx)
{
    xtt_error_code rc;

    // 1) Parse ClientInit and initialize our handshake_context using it.
    rc = parse_client_init(ctx_out, client_init);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

    // 2) Set message type.
    *xtt_access_msg_type(out_buffer) = XTT_SERVERINITANDATTEST_MSG;

    // 3) Set length.
    short_to_bigendian(xtt_serverinitandattest_total_length(ctx_out->base.version, ctx_out->base.suite_spec),
                       xtt_access_length(out_buffer));

    // 4) Set version.
    *xtt_access_version(out_buffer) = ctx_out->base.version;

    // 5) Set suite spec.
    short_to_bigendian(ctx_out->base.suite_spec,
                       xtt_serverinitandattest_access_suite_spec(out_buffer, ctx_out->base.version));

    // 6) Copy own Diffie-Hellman public key.
    ctx_out->base.copy_dh_pubkey(xtt_serverinitandattest_access_ecdhe_key(out_buffer,
                                                                          ctx_out->base.version),
                                 NULL,
                                 &ctx_out->base);

    // 7) Generate ServerCookie
    rc = build_server_cookie(xtt_serverinitandattest_access_server_cookie(out_buffer,
                                                                          ctx_out->base.version,
                                                                          ctx_out->base.suite_spec),
                             &ctx_out->base,
                             cookie_ctx);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

    // 8) Copy own certificate.
    memcpy(xtt_encrypted_serverinitandattest_access_certificate(ctx_out->base.buffer, 
                                                                ctx_out->base.version),
           certificate_ctx->serialized_certificate,
           xtt_server_certificate_length(ctx_out->base.suite_spec));

    // 9) Create signature.
    rc = generate_server_signature(xtt_encrypted_serverinitandattest_access_signature(ctx_out->base.buffer,
                                                                                      ctx_out->base.version,
                                                                                      ctx_out->base.suite_spec),
                                   client_init,
                                   out_buffer,
                                   ctx_out->base.buffer,
                                   &ctx_out->base,
                                   certificate_ctx);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

    // 9ii) Copy signature for later, too.
    memcpy(ctx_out->base.server_signature_buffer,
           xtt_encrypted_serverinitandattest_access_signature(ctx_out->base.buffer,
                                                              ctx_out->base.version,
                                                              ctx_out->base.suite_spec),
           certificate_ctx->signature_length);

    // 10) Run Diffie-Hellman and get handshake AEAD keys.
    // TODO: Move this earlier, in case it fails?
    rc = derive_handshake_keys(&ctx_out->base,
                               client_init,
                               out_buffer,
                               xtt_serverinitandattest_access_server_cookie(out_buffer,
                                                                            ctx_out->base.version,
                                                                            ctx_out->base.suite_spec),
                               xtt_clientinit_access_ecdhe_key(client_init,
                                                               ctx_out->base.version),
                               0);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

    // 11) AEAD encrypt the message
    uint16_t encrypted_len;
    rc = ctx_out->base.encrypt(out_buffer + xtt_serverinitandattest_unencrypted_part_length(ctx_out->base.version,
                                                                                            ctx_out->base.suite_spec),
                               &encrypted_len,
                               ctx_out->base.buffer,
                               xtt_serverinitandattest_encrypted_part_length(ctx_out->base.version,
                                                                             ctx_out->base.suite_spec),
                               out_buffer,
                               xtt_serverinitandattest_unencrypted_part_length(ctx_out->base.version,
                                                                               ctx_out->base.suite_spec),
                               &ctx_out->base);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_ERROR_SUCCESS == rc) {
        // 12) Report ServerInitAndAttest message length.
        *out_length = xtt_serverinitandattest_unencrypted_part_length(ctx_out->base.version, ctx_out->base.suite_spec)
                        + encrypted_len;
        assert(xtt_serverinitandattest_total_length(ctx_out->base.version, ctx_out->base.suite_spec) == *out_length);

        return XTT_ERROR_SUCCESS;
    } else {
        (void)build_error_msg(out_buffer, out_length, ctx_out->base.version);

        return rc;
    }
}

xtt_error_code
xtt_preparse_serverinitandattest(xtt_certificate_root_id *claimed_root_out,
                                 const unsigned char* server_init_and_attest,
                                 struct xtt_client_handshake_context* handshake_ctx)
{
    xtt_error_code rc;

    // 1) Parse ServerInitAndAttest,
    //  get the handshake AEAD keys,
    //  and AEAD-decrypt-and-authenticate the ServerInitAndAttest.
    rc = parse_server_initandattest(handshake_ctx, server_init_and_attest);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_ERROR_SUCCESS == rc) {
        //  2) Get the root_id claimed in the server's certificate.
        unsigned char *server_initandattest_decryptedpart = handshake_ctx->base.server_initandattest_buffer;
        memcpy(claimed_root_out->data,
               xtt_server_certificate_access_rootid(xtt_encrypted_serverinitandattest_access_certificate(server_initandattest_decryptedpart,
                                                                                                         handshake_ctx->base.version)),
               sizeof(xtt_certificate_root_id));
        return XTT_ERROR_SUCCESS;
    } else {
        *claimed_root_out = xtt_null_server_root_id;
        return rc;
    }
}

xtt_error_code
xtt_build_identity_client_attest(unsigned char* out_buffer,
                                 uint16_t* out_length,
                                 const unsigned char* server_init_and_attest,
                                 const struct xtt_server_root_certificate_context* root_server_certificate,
                                 const xtt_client_id* requested_client_id,
                                 const xtt_client_id* intended_server_client_id,
                                 struct xtt_daa_context* daa_ctx,
                                 struct xtt_client_handshake_context* handshake_ctx)
{
    xtt_error_code rc;

    // 1) Check server signature
    rc = verify_server_signature(xtt_encrypted_serverinitandattest_access_signature(handshake_ctx->base.server_initandattest_buffer,
                                                                                    handshake_ctx->base.version,
                                                                                    handshake_ctx->base.suite_spec),
                                 intended_server_client_id,
                                 root_server_certificate,
                                 handshake_ctx->base.client_init_buffer,
                                 server_init_and_attest,
                                 handshake_ctx->base.server_initandattest_buffer,
                                 handshake_ctx);
    if (XTT_ERROR_SUCCESS != rc)
        return rc;

    // 2) Set message type.
    *xtt_access_msg_type(out_buffer) = XTT_ID_CLIENTATTEST_MSG;

    // 3) Set length.
    short_to_bigendian(xtt_identityclientattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec),
                       xtt_access_length(out_buffer));

    // 4) Set version.
    *xtt_access_version(out_buffer) = handshake_ctx->base.version;

    // 5) Set suite spec.
    short_to_bigendian(handshake_ctx->base.suite_spec,
                       xtt_identityclientattest_access_suite_spec(out_buffer, handshake_ctx->base.version));

    // 6) Copy server cookie
    memcpy(xtt_identityclientattest_access_servercookie(out_buffer, handshake_ctx->base.version),
           xtt_serverinitandattest_access_server_cookie(server_init_and_attest,
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
                                (unsigned char*)xtt_serverinitandattest_access_server_cookie(server_init_and_attest,
                                                                                             handshake_ctx->base.version,
                                                                                             handshake_ctx->base.suite_spec),
                                xtt_encrypted_serverinitandattest_access_certificate(handshake_ctx->base.server_initandattest_buffer,
                                                                                     handshake_ctx->base.version),
                                xtt_encrypted_serverinitandattest_access_signature(handshake_ctx->base.server_initandattest_buffer,
                                                                                   handshake_ctx->base.version,
                                                                                   handshake_ctx->base.suite_spec),
                                out_buffer,
                                handshake_ctx->base.buffer,
                                handshake_ctx);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

    // 9) Copy GID.
    memcpy(xtt_encrypted_identityclientattest_access_gid(handshake_ctx->base.buffer,
                                                         handshake_ctx->base.version,
                                                         handshake_ctx->base.suite_spec),
           daa_ctx->gid.data,
           sizeof(xtt_daa_group_id));

    // 10) Copy my clientID.
    memcpy(xtt_encrypted_identityclientattest_access_id(handshake_ctx->base.buffer,
                                                        handshake_ctx->base.version,
                                                        handshake_ctx->base.suite_spec),
           requested_client_id->data,
           sizeof(xtt_client_id));

    // 11) Create DAA signature.
    rc = generate_daa_signature(xtt_encrypted_identityclientattest_access_daasignature(handshake_ctx->base.buffer,
                                                                                       handshake_ctx->base.version,
                                                                                       handshake_ctx->base.suite_spec),
                                (unsigned char*)xtt_serverinitandattest_access_server_cookie(server_init_and_attest,
                                                                                             handshake_ctx->base.version,
                                                                                             handshake_ctx->base.suite_spec),
                                xtt_encrypted_serverinitandattest_access_certificate(handshake_ctx->base.server_initandattest_buffer,
                                                                                     handshake_ctx->base.version),
                                xtt_encrypted_serverinitandattest_access_signature(handshake_ctx->base.server_initandattest_buffer,
                                                                                   handshake_ctx->base.version,
                                                                                   handshake_ctx->base.suite_spec),
                                out_buffer,
                                handshake_ctx->base.buffer,
                                &handshake_ctx->base,
                                daa_ctx);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

    // 12) AEAD encrypt the message
    uint16_t encrypted_len;
    rc = handshake_ctx->base.encrypt(out_buffer + xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version),
                                     &encrypted_len,
                                     handshake_ctx->base.buffer,
                                     xtt_identityclientattest_encrypted_part_length(handshake_ctx->base.version,
                                                                                    handshake_ctx->base.suite_spec),
                                     out_buffer,
                                     xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version),
                                     &handshake_ctx->base);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_ERROR_SUCCESS == rc) {
        // 13) Report Identity_CLientAttest message length.
        *out_length = xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version)
                        + encrypted_len;
        assert(xtt_identityclientattest_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec) == *out_length);

        return XTT_ERROR_SUCCESS;
    } else {
        (void)build_error_msg(out_buffer, out_length, handshake_ctx->base.version);

        return rc;
    }
}

xtt_error_code
xtt_pre_parse_client_attest(xtt_client_id* client_id_out,
                            xtt_daa_group_id* daa_group_id_out,
                            const unsigned char* client_attest,
                            struct xtt_server_cookie_context* cookie_ctx,
                            struct xtt_server_handshake_context* handshake_ctx)
{
    // 1) Get message type.
    xtt_msg_type msg_type = *xtt_access_msg_type(client_attest);
    if (XTT_ID_CLIENTATTEST_MSG != msg_type
            && XTT_SESSION_CLIENTATTEST_NOPAYLOAD_MSG != msg_type
            && XTT_SESSION_CLIENTATTEST_PAYLOAD_MSG != msg_type)
        return XTT_ERROR_INCORRECT_TYPE;

    // 2) Check the length of the ClientAttest message.
    uint16_t clientattest_length;
    bigendian_to_short(xtt_access_length(client_attest),
                       &clientattest_length);
    uint16_t minimum_length = sizeof(xtt_msg_type_raw)
        + sizeof(xtt_length)
        + sizeof(xtt_version_raw)
        + sizeof(xtt_suite_spec_raw);
    if (clientattest_length < minimum_length)
        return XTT_ERROR_INCORRECT_LENGTH;
    xtt_version_raw claimed_version = *xtt_access_version(client_attest);
    xtt_suite_spec claimed_suite_spec;
    xtt_suite_spec_raw claimed_suite_spec_raw;
    bigendian_to_short(xtt_identityclientattest_access_suite_spec(client_attest,
                                                                  claimed_version),
                       &claimed_suite_spec_raw);
    claimed_suite_spec = claimed_suite_spec_raw;
    if (clientattest_length != xtt_identityclientattest_total_length(claimed_version, claimed_suite_spec))
        return XTT_ERROR_INCORRECT_LENGTH;

    // 3) Check client's version and suite_spec
    if (claimed_version != handshake_ctx->base.version)
        return XTT_ERROR_UNKNOWN_VERSION;

    if (claimed_suite_spec != handshake_ctx->base.suite_spec)
        return XTT_ERROR_UNKNOWN_SUITE_SPEC;

    xtt_error_code rc;

    // 4) Check that client's echoed server_cookie is the one we sent.
    // TODO: We probably don't need to do this, the signature will validate the cookie (it's just a nonce)
    rc = validate_server_cookie((xtt_server_cookie*)xtt_identityclientattest_access_servercookie(client_attest,
                                                                                                 handshake_ctx->base.version),
                                &handshake_ctx->base,
                                cookie_ctx);
    if (XTT_ERROR_SUCCESS != rc)
        return rc;

    // 5) AEAD decrypt the message
    switch (msg_type) {
        case XTT_ID_CLIENTATTEST_MSG: {
            uint16_t decrypted_len;
            assert(sizeof(handshake_ctx->base.clientattest_buffer) >= xtt_identityclientattest_encrypted_part_length(handshake_ctx->base.version,
                                                                                                                handshake_ctx->base.suite_spec));
            rc = handshake_ctx->base.decrypt(handshake_ctx->base.clientattest_buffer,
                                             &decrypted_len,
                                             client_attest + xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version),
                                             xtt_identityclientattest_encrypted_part_length(handshake_ctx->base.version,
                                                                                            handshake_ctx->base.suite_spec)
                                                   + handshake_ctx->base.mac_length,
                                             client_attest,
                                             xtt_identityclientattest_unencrypted_part_length(handshake_ctx->base.version),
                                             &handshake_ctx->base);
            if (XTT_ERROR_SUCCESS != rc)
                return rc;

            // 7) Copy claimed DAA GID.
            memcpy(daa_group_id_out->data,
                   xtt_encrypted_identityclientattest_access_gid(handshake_ctx->base.clientattest_buffer,
                                                                 handshake_ctx->base.version,
                                                                 handshake_ctx->base.suite_spec),
                   sizeof(xtt_daa_group_id));

            // 8) Copy requested ClientID
            memcpy(client_id_out->data,
                   xtt_encrypted_identityclientattest_access_id(handshake_ctx->base.clientattest_buffer,
                                                                handshake_ctx->base.version,
                                                                handshake_ctx->base.suite_spec),
                   sizeof(xtt_client_id));

            break;
        }
        case XTT_SESSION_CLIENTATTEST_PAYLOAD_MSG:
        case XTT_SESSION_CLIENTATTEST_NOPAYLOAD_MSG:
            // TODO: Implement this
            return XTT_ERROR_INCORRECT_TYPE;
        case XTT_CLIENTINIT_MSG:
        case XTT_SERVERINITANDATTEST_MSG:
        case XTT_ID_SERVERFINISHED_MSG:
        case XTT_SESSION_SERVERFINISHED_MSG:
        case XTT_RECORD_REGULAR_MSG:
        case XTT_ERROR_MSG:
            return XTT_ERROR_INCORRECT_TYPE;
    }

    return XTT_ERROR_SUCCESS;
}

xtt_error_code
xtt_build_identity_server_finished(unsigned char *out_buffer,
                                   uint16_t *out_length,
                                   const unsigned char* client_attest,
                                   xtt_client_id *client_id,
                                   struct xtt_daa_group_public_key_context* daa_group_pub_key_ctx,
                                   struct xtt_server_certificate_context *certificate_ctx,
                                   struct xtt_server_handshake_context* handshake_ctx)
{
    xtt_error_code rc;

    // 1) Verify DAA Signature
    rc = verify_daa_signature(xtt_encrypted_identityclientattest_access_daasignature(handshake_ctx->base.clientattest_buffer,
                                                                                     handshake_ctx->base.version,
                                                                                     handshake_ctx->base.suite_spec),
                              (unsigned char*)&handshake_ctx->base.server_cookie,
                              handshake_ctx->base.server_signature_buffer,
                              client_attest,
                              handshake_ctx->base.clientattest_buffer,
                              daa_group_pub_key_ctx,
                              certificate_ctx,
                              &handshake_ctx->base);
    if (XTT_ERROR_SUCCESS != rc)
        return rc;

    // 2) Read-out the claimed longterm_key.
    handshake_ctx->read_longterm_key(handshake_ctx,
                                     NULL,
                                     xtt_encrypted_identityclientattest_access_longtermkey(handshake_ctx->base.clientattest_buffer,
                                                                                           handshake_ctx->base.version));

    // 3) Verify longterm_key_signature
    rc = verify_client_longterm_signature(xtt_encrypted_identityclientattest_access_longtermsignature(handshake_ctx->base.clientattest_buffer,
                                                                                                      handshake_ctx->base.version,
                                                                                                      handshake_ctx->base.suite_spec),
                                          (unsigned char*)&handshake_ctx->base.server_cookie,
                                          handshake_ctx->base.server_signature_buffer,
                                          client_attest,
                                          handshake_ctx->base.clientattest_buffer,
                                          certificate_ctx,
                                          handshake_ctx);
    if (XTT_ERROR_SUCCESS != rc)
        return rc;

    // 4) Set message type.
    *xtt_access_msg_type(out_buffer) = XTT_ID_SERVERFINISHED_MSG;

    // 5) Set length.
    short_to_bigendian(xtt_identityserverfinished_total_length(handshake_ctx->base.version,
                                                               handshake_ctx->base.suite_spec),
                       xtt_access_length(out_buffer));

    // 6) Set version.
    *xtt_access_version(out_buffer) = handshake_ctx->base.version;

    // 7) Set suite spec.
    short_to_bigendian(handshake_ctx->base.suite_spec,
                       xtt_identityserverfinished_access_suite_spec(out_buffer, handshake_ctx->base.version));

    // 8) Set the client's id.
    memcpy(xtt_encrypted_identityserverfinished_access_id(handshake_ctx->base.buffer,
                                                          handshake_ctx->base.version),
           client_id->data,
           sizeof(xtt_client_id));

    // 9) Set the longterm_key (echo)
    memcpy(xtt_encrypted_identityserverfinished_access_longtermkey(handshake_ctx->base.buffer,
                                                                   handshake_ctx->base.version),
           xtt_encrypted_identityclientattest_access_longtermkey(handshake_ctx->base.clientattest_buffer,
                                                                 handshake_ctx->base.version),
           handshake_ctx->base.longterm_key_length);

    // 10) AEAD encrypt the message
    uint16_t encrypted_len;
    rc = handshake_ctx->base.encrypt(out_buffer + xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version),
                                     &encrypted_len,
                                     handshake_ctx->base.buffer,
                                     xtt_identityserverfinished_encrypted_part_length(handshake_ctx->base.version,
                                                                                      handshake_ctx->base.suite_spec),
                                     out_buffer,
                                     xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version),
                                     &handshake_ctx->base);
    if (XTT_ERROR_SUCCESS != rc)
        goto finish;

finish:
    if (XTT_ERROR_SUCCESS == rc) {
        // 11) Report ServerFinished message length.
        *out_length = xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version)
                        + encrypted_len;
        assert(xtt_identityserverfinished_total_length(handshake_ctx->base.version, handshake_ctx->base.suite_spec) == *out_length);

        return XTT_ERROR_SUCCESS;
    } else {
        (void)build_error_msg(out_buffer, out_length, handshake_ctx->base.version);

        return rc;
    }
}

xtt_error_code
xtt_parse_identity_server_finished(xtt_client_id* client_id,
                                   const unsigned char* identity_server_finished,
                                   struct xtt_client_handshake_context* handshake_ctx)
{
    // 1) Check the length of the ServerFinished message.
    uint16_t serverfinished_length;
    bigendian_to_short(xtt_access_length(identity_server_finished), &serverfinished_length);
    uint16_t minimum_length = sizeof(xtt_msg_type_raw)
        + sizeof(xtt_length)
        + sizeof(xtt_version_raw)
        + sizeof(xtt_suite_spec_raw);
    if (serverfinished_length < minimum_length)
        return XTT_ERROR_INCORRECT_LENGTH;
    xtt_version_raw claimed_version = *xtt_access_version(identity_server_finished);
    xtt_suite_spec claimed_suite_spec;
    xtt_suite_spec_raw claimed_suite_spec_raw;
    bigendian_to_short(xtt_identityserverfinished_access_suite_spec(identity_server_finished,
                                                                    claimed_version),
                       &claimed_suite_spec_raw);
    claimed_suite_spec = claimed_suite_spec_raw;
    if (serverfinished_length != xtt_identityserverfinished_total_length(claimed_version, claimed_suite_spec))
        return XTT_ERROR_INCORRECT_LENGTH;

    // 2) Check message type.
    if (XTT_ID_SERVERFINISHED_MSG != *xtt_access_msg_type(identity_server_finished))
        return XTT_ERROR_INCORRECT_TYPE;

    // 3) Check server's version and suite_spec
    if (claimed_version != handshake_ctx->base.version)
        return XTT_ERROR_UNKNOWN_VERSION;

    if (claimed_suite_spec != handshake_ctx->base.suite_spec)
        return XTT_ERROR_UNKNOWN_SUITE_SPEC;

    xtt_error_code rc;

    // 4) AEAD decrypt the message
    uint16_t decrypted_len;
    assert(sizeof(handshake_ctx->base.buffer) >= xtt_identityserverfinished_encrypted_part_length(handshake_ctx->base.version,
                                                                                             handshake_ctx->base.suite_spec));

    rc = handshake_ctx->base.decrypt(handshake_ctx->base.buffer,
                                     &decrypted_len,
                                     identity_server_finished + xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version),
                                     xtt_identityserverfinished_encrypted_part_length(handshake_ctx->base.version,
                                                                                      handshake_ctx->base.suite_spec)
                                           + handshake_ctx->base.mac_length,
                                     identity_server_finished,
                                     xtt_identityserverfinished_unencrypted_part_length(handshake_ctx->base.version),
                                     &handshake_ctx->base);
    if (XTT_ERROR_SUCCESS != rc)
        return rc;

    // 5) Get the client_id sent by the server (and make sure it matches ours, if we requested one).
    if (0 == xtt_crypto_memcmp(xtt_null_client_id.data, client_id->data, sizeof(xtt_client_id))) {
        memcpy(client_id,
               xtt_encrypted_identityserverfinished_access_id(handshake_ctx->base.buffer, handshake_ctx->base.version),
               sizeof(xtt_client_id));
    } else if (0 != xtt_crypto_memcmp(client_id->data,
                                      xtt_encrypted_identityserverfinished_access_id(handshake_ctx->base.buffer, handshake_ctx->base.version),
                                      sizeof(xtt_client_id))) {
        return XTT_ERROR_BAD_FINISH;
    }

    if (0 != handshake_ctx->compare_longterm_keys(xtt_encrypted_identityserverfinished_access_longtermkey(handshake_ctx->base.buffer, handshake_ctx->base.version),
                                                  handshake_ctx)) {
        return XTT_ERROR_BAD_FINISH;
    }

    return XTT_ERROR_SUCCESS;
}

xtt_error_code
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
        return XTT_ERROR_INCORRECT_LENGTH;
    ctx_out->base.version = *xtt_access_version(client_init);
    xtt_suite_spec_raw suite_spec_raw;
    bigendian_to_short(xtt_clientinit_access_suite_spec(client_init,
                                                        ctx_out->base.version),
                       &suite_spec_raw);
    ctx_out->base.suite_spec = suite_spec_raw;
    if (client_init_length != xtt_clientinit_length(ctx_out->base.version, ctx_out->base.suite_spec))
        return XTT_ERROR_INCORRECT_LENGTH;

    // 2) Check message type.
    if (XTT_CLIENTINIT_MSG != *xtt_access_msg_type(client_init))
        return XTT_ERROR_INCORRECT_TYPE;

    xtt_error_code rc;

    // 3) Initialize own context from version and suite_spec from client.
    rc = xtt_initialize_server_handshake_context(ctx_out,
                                                 ctx_out->base.version,
                                                 ctx_out->base.suite_spec);
    if (XTT_ERROR_SUCCESS != rc)
        return rc;

    return XTT_ERROR_SUCCESS;
}

xtt_error_code
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
        return XTT_ERROR_INCORRECT_LENGTH;
    xtt_version_raw claimed_version = *xtt_access_version(server_init_and_attest);
    xtt_suite_spec claimed_suite_spec;
    xtt_suite_spec_raw claimed_suite_spec_raw;
    bigendian_to_short(xtt_serverinitandattest_access_suite_spec(server_init_and_attest,
                                                                 claimed_version),
                       &claimed_suite_spec_raw);
    claimed_suite_spec = claimed_suite_spec_raw;
    if (serverinitandattest_length != xtt_serverinitandattest_total_length(claimed_version, claimed_suite_spec))
        return XTT_ERROR_INCORRECT_LENGTH;

    // 2) Check message type.
    if (XTT_SERVERINITANDATTEST_MSG != *xtt_access_msg_type(server_init_and_attest))
        return XTT_ERROR_INCORRECT_TYPE;

    // 3) Check server's version and suite_spec
    if (claimed_version != handshake_ctx->base.version)
        return XTT_ERROR_UNKNOWN_VERSION;

    if (claimed_suite_spec != handshake_ctx->base.suite_spec)
        return XTT_ERROR_UNKNOWN_SUITE_SPEC;

    xtt_error_code rc;

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
    if (XTT_ERROR_SUCCESS != rc)
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
        return XTT_ERROR_CRYPTO;

    return XTT_ERROR_SUCCESS;
}

xtt_error_code
build_error_msg(unsigned char *out_buffer,
                uint16_t *out_length,
                xtt_version version)
{
    *xtt_access_msg_type(out_buffer) = XTT_ERROR_MSG;

    short_to_bigendian(xtt_error_msg_length(version),
                       xtt_access_length(out_buffer));
    *xtt_access_version(out_buffer) = version;

    *out_length = xtt_error_msg_length(version);

    return XTT_ERROR_SUCCESS;
}
