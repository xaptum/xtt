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

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_socket.h>
#include <ecdaa.h>

#include "test-utils.h"

#include "../src/internal/message_utils.h"
#include "../src/internal/byte_utils.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

uint8_t memory_pool[5000];

static
int
read_nvram(unsigned char *out,
           uint16_t length,
           TPM_HANDLE index,
           TSS2_SYS_CONTEXT *sapi_context);

static
int
read_gpk(xtt_daa_group_pub_key_lrsw *gpk_out);

static
int
read_cred(xtt_daa_credential_lrsw *cred_out);

// TODO: We don't use the public key for signing, so ECDAA shouldn't require it of us
// For now, we're using a dummy key.
const uint8_t tpm_pub_key[] = {0X4, 0XF4, 0XB3, 0XB2, 0X99, 0XD6, 0X73, 0XF3, 0XB0, 0XD3, 0X43, 0XB2, 0X33, 0X89, 0X21, 0X8D, 0XC1, 0XF3, 0X34, 0X75, 0XD7, 0XEF, 0X59, 0X9F, 0XA7, 0X39, 0X94, 0XC0, 0XA1, 0XDB, 0X77, 0XB, 0X64, 0XB, 0XB5, 0XCD, 0XE6, 0X43, 0XF7, 0XC1, 0X1F, 0XC3, 0XA5, 0X33, 0X61, 0XD7, 0XEA, 0X5C, 0XF2, 0X44, 0X52, 0X28, 0X92, 0XCE, 0X29, 0X65, 0XFD, 0XA8, 0X84, 0X73, 0XB, 0X2, 0X49, 0XB2, 0X2C};

TPM_HANDLE key_handle_g = 0x81000000;
TPM_HANDLE gpk_handle_g = 0x1600000;
TPM_HANDLE cred_handle_g = 0x1600001;
const char *tpm_hostname_g = "localhost";
const char *tpm_port_g = "2321";
const char *tpm_password = NULL;
uint16_t tpm_password_len = 0;

static
void generate_server_certificates(unsigned char *cert_serialized_out,
                                  xtt_client_id *server_id,
                                  xtt_ed25519_priv_key *server_private_key,
                                  xtt_certificate_root_id *root_id,
                                  xtt_ed25519_pub_key *root_public_key);

int main()
{
    xtt_error_code rc;
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
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);

    // 8) Get GPK from TPM.
    xtt_daa_group_pub_key_lrsw gpk;
    rc = read_gpk(&gpk);
    EXPECT_EQ(0, rc);
    xtt_daa_group_id gid = {.data={0}};
    int hash_ret = crypto_hash_sha256(gid.data, gpk.data, sizeof(gpk));
    EXPECT_EQ(0, hash_ret);

    // 6) Set client's DAA context.
    xtt_client_id my_client_id = {.data={4,2,7,4,2,8,3,9,4,2,4,3,3,6,5,8}};
    struct xtt_daa_context daa_ctx;
    xtt_daa_credential_lrsw cred;
    rc = read_cred(&cred);
    EXPECT_EQ(0, rc);
    char *basename = "BASENAME";
    uint16_t basename_len = (uint16_t)strlen(basename);

    struct ecdaa_tpm_context tpm_ctx;
    int ret = ecdaa_tpm_context_init_socket(&tpm_ctx,
                                            tpm_pub_key,
                                            key_handle_g,
                                            tpm_hostname_g,
                                            tpm_port_g,
                                            tpm_password,
                                            tpm_password_len);
    EXPECT_EQ(0, ret);

    rc = xtt_initialize_daa_context_lrswTPM(&daa_ctx,
                                            &gid,
                                            &cred,
                                            (unsigned char*)basename,
                                            basename_len,
                                            (struct xtt_daa_tpm_context*)&tpm_ctx);
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);
    //////////////////////////////

    // 1) Create client's handshake context
    struct xtt_client_handshake_context client_handshake_ctx;
    rc = xtt_initialize_client_handshake_context(&client_handshake_ctx,
                                                 version,
                                                 suite_spec);
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);

    // 2) Send ClientInit
    uint16_t client_init_send_length;
    rc = xtt_build_client_init(client_to_server,
                               &client_init_send_length,
                               &client_handshake_ctx);
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);
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
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);
    EXPECT_EQ(xtt_get_message_type(server_to_client), XTT_SERVERINITANDATTEST_MSG);
    EXPECT_EQ(xtt_get_message_length(server_to_client), server_initandattest_send_length);

    // 4) Parse ServerInitAndAttest
    xtt_certificate_root_id claimed_root_id;
    rc = xtt_preparse_serverinitandattest(&claimed_root_id,
                                          server_to_client,
                                          &client_handshake_ctx);
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);
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
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);
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
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);
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
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);
    EXPECT_EQ(0, memcmp(server_handshake_ctx.clients_longterm_key.ed25519.data,
                        client_handshake_ctx.longterm_key.ed25519.data,
                        server_handshake_ctx.base.longterm_key_length));
    EXPECT_EQ(xtt_get_message_type(server_to_client), XTT_ID_SERVERFINISHED_MSG);
    EXPECT_EQ(xtt_get_message_length(server_to_client), identity_serverfinished_length);

    // 12) Parse the Identity_serverFinished
    rc = xtt_parse_identity_server_finished(&my_client_id,
                                            server_to_client,
                                            &client_handshake_ctx);
    EXPECT_EQ(XTT_ERROR_SUCCESS, rc);

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

int
read_nvram(unsigned char *out,
           uint16_t size,
           TPM_HANDLE index,
           TSS2_SYS_CONTEXT *sapi_context)
{
    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    uint16_t data_offset = 0;

    uint32_t auth_handle = TPM_RH_OWNER;

    while (size > 0) {
        uint16_t bytes_to_read = size;

        TPM2B_MAX_NV_BUFFER nv_data = {.size=0};

        TSS2_RC rval = Tss2_Sys_NV_Read(sapi_context,
                                        auth_handle,
                                        index,
                                        &sessionsData,
                                        bytes_to_read,
                                        data_offset,
                                        &nv_data,
                                        &sessionsDataOut);

        if (rval != TSS2_RC_SUCCESS) {
            return -1;
        }

        size -= nv_data.size;

        memcpy(out + data_offset, nv_data.buffer, nv_data.size);
        data_offset += nv_data.size;
    }

    return 0;
}

TSS2_SYS_CONTEXT*
init_sapi_ctx(void)
{
    size_t tcti_ctx_size = tss2_tcti_getsize_socket();
    TEST_ASSERT(tcti_ctx_size <= sizeof(memory_pool));
    TSS2_TCTI_CONTEXT *tcti_ctx = (TSS2_TCTI_CONTEXT*)&memory_pool[0];

    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    TEST_ASSERT(sapi_ctx_size <= (sizeof(memory_pool) - tcti_ctx_size));
    TSS2_SYS_CONTEXT *sapi_context = (TSS2_SYS_CONTEXT*)&memory_pool[tcti_ctx_size];

    TSS2_RC init_ret;

    init_ret = tss2_tcti_init_socket(tpm_hostname_g, tpm_port_g, tcti_ctx);
    EXPECT_EQ(TSS2_RC_SUCCESS, init_ret);

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    init_ret = Tss2_Sys_Initialize(sapi_context,
                                   sapi_ctx_size,
                                   tcti_ctx,
                                   &abi_version);
    EXPECT_EQ(TSS2_RC_SUCCESS, init_ret);

    return sapi_context;
}

int
read_cred(xtt_daa_credential_lrsw *cred_out)
{
    int ret;
    
    TSS2_SYS_CONTEXT *sapi_context = init_sapi_ctx();

    ret = read_nvram(cred_out->data,  
                     sizeof(xtt_daa_credential_lrsw),
                     cred_handle_g,
                     sapi_context);
    if (0 != ret) {
        return ret;
    }

    return 0;
}

int
read_gpk(xtt_daa_group_pub_key_lrsw *gpk_out)
{
    int ret;
    
    TSS2_SYS_CONTEXT *sapi_context = init_sapi_ctx();

    ret = read_nvram(gpk_out->data,
                     sizeof(xtt_daa_group_pub_key_lrsw),
                     gpk_handle_g,
                     sapi_context);
    if (0 != ret) {
        return ret;
    }

    return 0;
}
