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

#include <xtt.h>

#include <sodium.h>

#include <ecdaa.h>

#include "test-utils.h"

#include "../src/internal/message_utils.h"
#include "../src/internal/byte_utils.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

xtt_daa_group_pub_key_lrsw gpk = {.data={
    0x04, 0x27, 0xd4, 0x35, 0xbf, 0xc7, 0x1d, 0x4a, 0x42, 0xb1, 0xd2, 0x26,
    0x25, 0x54, 0xfe, 0x12, 0x54, 0x84, 0xbc, 0x67, 0x2e, 0xe7, 0xfb, 0x68,
    0xf7, 0x00, 0xb3, 0x7f, 0x2a, 0xb4, 0x91, 0x61, 0xb8, 0xd3, 0xed, 0x78,
    0x53, 0x42, 0x26, 0x26, 0x48, 0x27, 0xaf, 0x66, 0xfe, 0xcf, 0xfb, 0xb3,
    0x8d, 0xd0, 0xcc, 0x76, 0xff, 0x23, 0x38, 0x36, 0xc4, 0x9b, 0x5a, 0xfa,
    0x58, 0x0c, 0x70, 0x34, 0xca, 0xb4, 0xf5, 0xf7, 0xfd, 0x9d, 0x06, 0x7e,
    0xc7, 0xad, 0x6e, 0xb4, 0x7a, 0x92, 0x1a, 0xd4, 0x08, 0x27, 0xee, 0xdd,
    0xf2, 0xf6, 0x82, 0xf6, 0x94, 0x50, 0xdd, 0xba, 0xec, 0x99, 0x37, 0xca,
    0x11, 0x76, 0x80, 0xf7, 0xdc, 0xe8, 0xd9, 0x20, 0x0b, 0xa6, 0x99, 0xa7,
    0x11, 0x6c, 0xf4, 0xc2, 0x5a, 0x34, 0x05, 0x52, 0x1e, 0x19, 0x30, 0x40,
    0xa1, 0x0e, 0xe9, 0x10, 0x4d, 0xd5, 0xc0, 0x18, 0xdf, 0x04, 0xee, 0x9c,
    0x97, 0x24, 0xaf, 0x83, 0xe6, 0x5a, 0x91, 0xcc, 0x0f, 0xcf, 0x5c, 0xfe,
    0xa9, 0x34, 0x39, 0x81, 0x4d, 0xfe, 0x05, 0xc8, 0xca, 0x0c, 0xd8, 0x5e,
    0xf0, 0x55, 0xad, 0xf8, 0x1d, 0xd0, 0xf1, 0xd1, 0x3b, 0x90, 0x61, 0xac,
    0x82, 0x12, 0xfb, 0x07, 0x78, 0xee, 0xdb, 0xd6, 0x2e, 0xd7, 0xe0, 0x16,
    0x89, 0xe1, 0x27, 0x8f, 0xac, 0xde, 0xcd, 0x71, 0x39, 0xe7, 0xec, 0x88,
    0x01, 0xa8, 0xdb, 0xc8, 0xa7, 0x8e, 0x36, 0x90, 0xce, 0xd2, 0x1e, 0x32,
    0x79, 0xc4, 0x6a, 0x88, 0x3c, 0x8a, 0xe5, 0x63, 0xb0, 0xd6, 0xb1, 0x31,
    0x9d, 0x23, 0x19, 0x2a, 0xc2, 0x94, 0xb6, 0x7d, 0xc0, 0x0e, 0xd3, 0xfb,
    0x96, 0xbd, 0xe6, 0x48, 0xec, 0xe3, 0x20, 0xee, 0xd1, 0x0d, 0x5a, 0x93,
    0x15, 0x8c, 0xdb, 0x2d, 0x93, 0xec, 0xff, 0x0f, 0x20, 0x9f, 0x6e, 0xfd,
    0x05, 0x3a, 0x18, 0xe3, 0xf6, 0xd8
}};

xtt_daa_credential_lrsw cred = {.data={
    0x04, 0xe1, 0x63, 0x6e, 0x34, 0x7c, 0x7f, 0xbc, 0x41, 0xc2, 0x0b, 0xf5,
    0x28, 0x7d, 0xb8, 0xb9, 0xbd, 0x77, 0x89, 0xb7, 0x3e, 0x0b, 0xda, 0x91,
    0xe1, 0xe1, 0x90, 0x1c, 0xcf, 0x06, 0x6f, 0xb0, 0x10, 0xd7, 0xab, 0x7a,
    0x3b, 0x8f, 0x29, 0x5a, 0xb3, 0x10, 0xd2, 0xba, 0xed, 0x57, 0x98, 0xed,
    0x2c, 0x2c, 0xa0, 0x4d, 0xa0, 0x2f, 0xfc, 0x03, 0x85, 0xd6, 0xc7, 0x08,
    0xfe, 0xfd, 0xab, 0x37, 0x5c, 0x04, 0xa4, 0x65, 0x2b, 0xf6, 0xa6, 0xb0,
    0x75, 0xda, 0x3b, 0xc7, 0x4d, 0x11, 0x0e, 0xa5, 0x22, 0x3b, 0x64, 0xcc,
    0x28, 0x3f, 0x8e, 0xc4, 0x91, 0x65, 0x25, 0xa8, 0x7e, 0x36, 0x67, 0xa4,
    0x53, 0xed, 0x42, 0xda, 0xbd, 0xdc, 0x49, 0xfe, 0xe9, 0xb0, 0x0a, 0x0c,
    0x76, 0x3c, 0x52, 0xae, 0xb1, 0x00, 0xb4, 0xa1, 0x90, 0x7c, 0xcc, 0x4e,
    0xe8, 0xe2, 0x4e, 0xb9, 0xf7, 0xa4, 0x91, 0xa7, 0xd1, 0x57, 0x04, 0x8a,
    0x71, 0x60, 0xca, 0x86, 0xf8, 0xc4, 0x67, 0x79, 0x68, 0x8c, 0x19, 0x59,
    0xf2, 0xb1, 0x58, 0x4e, 0xbe, 0x7a, 0xbb, 0xc5, 0x87, 0x2f, 0xbf, 0xed,
    0xe1, 0x6b, 0xba, 0xf1, 0xe0, 0x3b, 0xf6, 0x5f, 0xca, 0x23, 0xfa, 0x78,
    0xb9, 0x89, 0x91, 0xbd, 0x3a, 0x51, 0x1b, 0x0a, 0xbe, 0x7c, 0x1a, 0xdb,
    0x2a, 0xef, 0xc7, 0xb8, 0x5d, 0xbd, 0x51, 0xd5, 0x4d, 0x00, 0x5c, 0x7d,
    0x7a, 0xc4, 0xd1, 0x04, 0xd6, 0x53, 0xc8, 0xc3, 0x8f, 0xc9, 0xfb, 0x26,
    0xa8, 0xc8, 0xb7, 0xf6, 0x7f, 0x58, 0xb4, 0x64, 0x05, 0x8c, 0x1b, 0x8c,
    0xea, 0x26, 0x8f, 0x1c, 0x81, 0xcf, 0xb6, 0x37, 0x7b, 0x6b, 0x11, 0x36,
    0xa9, 0x9a, 0xd1, 0x0c, 0xf3, 0xfd, 0xc3, 0xe3, 0x9e, 0x72, 0x41, 0x97,
    0x51, 0x18, 0xca, 0x24, 0x29, 0xf2, 0xa4, 0x6f, 0xd5, 0x50, 0x30, 0x98,
    0x15, 0x68, 0x84, 0xf7, 0x2b, 0x5a, 0x80, 0x39
}};

xtt_daa_priv_key_lrsw daa_priv_key = {.data={
    0x0b, 0x8a, 0x76, 0xe0, 0xbf, 0x23, 0xf2, 0x1a, 0x5b, 0x54, 0x7d, 0x8c,
    0x97, 0xcf, 0x3f, 0xa0, 0xae, 0x72, 0xb6, 0x60, 0x29, 0x10, 0x18, 0x14,
    0x61, 0xb6, 0x58, 0x6a, 0x44, 0x97, 0xa1, 0xf7
}};

static
void generate_server_certificates(unsigned char *cert_serialized_out,
                                  xtt_client_id *server_id,
                                  xtt_ed25519_priv_key *server_private_key,
                                  xtt_certificate_root_id *root_id,
                                  xtt_ed25519_pub_key *root_public_key);

int main()
{
    xtt_return_code_type rc;
    unsigned char server_to_client[1024];
    unsigned char client_to_server[1024];

    xtt_version version = XTT_VERSION_ONE;
    // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512;
    // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B;
    xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_SHA512;
    // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B;

    ///// Initialize
    // 3) Create server's certificate context
    struct xtt_server_root_certificate_context root_certificate;
    xtt_certificate_root_id root_id;
    xtt_ed25519_pub_key root_public_key;
    xtt_client_id server_id;
    xtt_ed25519_priv_key server_private_key;
    unsigned char serialized_certificate[XTT_SERVER_CERTIFICATE_ED25519_LENGTH];
    generate_server_certificates(serialized_certificate, &server_id, &server_private_key, &root_id, &root_public_key);

    rc = xtt_initialize_server_root_certificate_context_ed25519(&root_certificate,
                                                                &root_id,
                                                                &root_public_key);
    EXPECT_EQ(0, rc);

    struct xtt_server_certificate_context cert_ctx;
    rc = xtt_initialize_server_certificate_context_ed25519(&cert_ctx,
                                                           serialized_certificate,
                                                           &server_private_key);
    EXPECT_EQ(0, rc);

    // 4) Create server's cookie context
    struct xtt_server_cookie_context cookie_ctx;
    rc = xtt_initialize_server_cookie_context(&cookie_ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);

    // 8) Get GID from the GPK
    xtt_daa_group_id gid = {.data={0}};
    int hash_ret = crypto_hash_sha256(gid.data, gpk.data, sizeof(gpk));
    EXPECT_EQ(0, hash_ret);

    // 6) Set client's DAA context.
    xtt_client_id my_client_id = {.data={4,2,7,4,2,8,3,9,4,2,4,3,3,6,5,8}};
    struct xtt_daa_context daa_ctx;
    EXPECT_EQ(0, rc);
    char *basename = "BASENAME";
    uint16_t basename_len = (uint16_t)strlen(basename);

    rc = xtt_initialize_daa_context_lrsw(&daa_ctx,
                                         &gid,
                                         &daa_priv_key,
                                         &cred,
                                         (unsigned char*)basename,
                                         basename_len);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);
    //////////////////////////////

    // 1) Create client's handshake context
    struct xtt_client_handshake_context client_handshake_ctx;
    rc = xtt_initialize_client_handshake_context(&client_handshake_ctx,
                                                 version,
                                                 suite_spec);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);

    // 2) Send ClientInit
    uint16_t client_init_send_length;
    rc = xtt_build_client_init(client_to_server,
                               &client_init_send_length,
                               &client_handshake_ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);
    EXPECT_EQ(xtt_clientinit_length(version, suite_spec), client_init_send_length);
    EXPECT_EQ(xtt_get_message_type(client_to_server), XTT_CLIENTINIT_MSG);
    EXPECT_EQ(xtt_get_message_length(client_to_server), client_init_send_length);

    // 3) Parse ClientInit and send ServerInitAndAttest
    uint16_t server_initandattest_send_length;
    struct xtt_server_handshake_context server_handshake_ctx;
    rc = xtt_build_server_init_and_attest(server_to_client,
                                          &server_initandattest_send_length,
                                          &server_handshake_ctx,
                                          client_to_server,
                                          &cert_ctx,
                                          &cookie_ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);
    EXPECT_EQ(xtt_get_message_type(server_to_client), XTT_SERVERINITANDATTEST_MSG);
    EXPECT_EQ(xtt_get_message_length(server_to_client), server_initandattest_send_length);

    // 4) Parse ServerInitAndAttest
    xtt_certificate_root_id claimed_root_id;
    rc = xtt_preparse_serverinitandattest(&claimed_root_id,
                                          server_to_client,
                                          &client_handshake_ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);
    EXPECT_EQ(0, memcmp(claimed_root_id.data, root_certificate.id.data, sizeof(xtt_certificate_root_id)));

    // 5) Send Identity_ClientAttest
    uint16_t identity_clientattest_length;
    rc = xtt_build_identity_client_attest(client_to_server,
                                          &identity_clientattest_length,
                                          server_to_client,
                                          &root_certificate,
                                          &my_client_id,
                                          &server_id,
                                          &daa_ctx,
                                          &client_handshake_ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);
    EXPECT_EQ(xtt_get_message_type(client_to_server), XTT_ID_CLIENTATTEST_MSG);
    EXPECT_EQ(xtt_get_message_length(client_to_server), identity_clientattest_length);

    // 6) Pre-parse Identity_ClientAttest
    xtt_client_id requested_client_id;
    xtt_daa_group_id claimed_gid;
    rc = xtt_pre_parse_client_attest(&requested_client_id,
                                     &claimed_gid,
                                     client_to_server,
                                     &cookie_ctx,
                                     &server_handshake_ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);
    EXPECT_EQ(0, memcmp(claimed_gid.data, gid.data, sizeof(xtt_daa_group_id)));
    EXPECT_EQ(0, memcmp(requested_client_id.data, my_client_id.data, sizeof(xtt_client_id)));

    // 10) Build DAA GPK context from GPK we looked up, using GID just read from Identity_ClientAttest
    struct xtt_daa_group_public_key_context gpk_ctx;
    rc = xtt_initialize_daa_group_public_key_context_lrsw(&gpk_ctx,
                                                          (unsigned char*)basename,
                                                          basename_len,
                                                          &gpk);

    // 11) Validate the DAA sig in the CLientAttest, and send the Identity_ServerFinished
    uint16_t identity_serverfinished_length;
    rc = xtt_build_identity_server_finished(server_to_client,
                                            &identity_serverfinished_length,
                                            client_to_server,
                                            &requested_client_id,
                                            &gpk_ctx,
                                            &cert_ctx,
                                            &server_handshake_ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);
    EXPECT_EQ(0, memcmp(server_handshake_ctx.clients_longterm_key.ed25519.data,
                        client_handshake_ctx.longterm_key.ed25519.data,
                        server_handshake_ctx.base.longterm_key_length));
    EXPECT_EQ(xtt_get_message_type(server_to_client), XTT_ID_SERVERFINISHED_MSG);
    EXPECT_EQ(xtt_get_message_length(server_to_client), identity_serverfinished_length);

    // 12) Parse the Identity_serverFinished
    rc = xtt_parse_identity_server_finished(&my_client_id,
                                            server_to_client,
                                            &client_handshake_ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, rc);

    // 13) Ensure client and server have consistent views of client's id and longterm_key
    EXPECT_EQ(0, memcmp(my_client_id.data, requested_client_id.data, sizeof(xtt_client_id))); 

    xtt_ed25519_pub_key servers_view_of_longterm_key, clients_view_of_longterm_key;
    rc = xtt_get_clients_longterm_key_ed25519(&servers_view_of_longterm_key, &server_handshake_ctx);
    EXPECT_EQ(0, rc);
    rc = xtt_get_my_longterm_key_ed25519(&clients_view_of_longterm_key, &client_handshake_ctx);
    EXPECT_EQ(0, rc);
    EXPECT_EQ(0, memcmp(servers_view_of_longterm_key.data, clients_view_of_longterm_key.data, sizeof(xtt_ed25519_pub_key))); 
}

void generate_server_certificates(unsigned char *cert_serialized_out,
                                  xtt_client_id *server_id,
                                  xtt_ed25519_priv_key *server_private_key,
                                  xtt_certificate_root_id *root_id,
                                  xtt_ed25519_pub_key *root_public_key)
{
    int rc;

    // TODO: Put this somewhere else
    assert(XTT_SERVER_CERTIFICATE_ED25519_LENGTH == xtt_server_certificate_length_fromsignaturetype(XTT_SERVER_SIGNATURE_TYPE_ED25519));

    // Create root certificate
    memcpy(root_id->data,
           "1234567890987654",
           sizeof(xtt_certificate_root_id));
    xtt_ed25519_priv_key root_priv_key;
    rc = xtt_crypto_create_ed25519_key_pair(root_public_key, &root_priv_key);
    EXPECT_EQ(0, rc);

    // Create server's certificate.
    memcpy(server_id->data, "4567890987654321", sizeof(xtt_client_id));

    xtt_ed25519_pub_key public_key;
    rc = xtt_crypto_create_ed25519_key_pair(&public_key, server_private_key);
    EXPECT_EQ(0, rc);

    xtt_certificate_expiry expiry;
    memcpy(expiry.data, "21001231", 8);

    rc = generate_server_certificate_ed25519(cert_serialized_out,
                                             server_id,
                                             &public_key,
                                             &expiry,
                                             root_id,
                                             &root_priv_key);
    EXPECT_EQ(0, rc);
}
