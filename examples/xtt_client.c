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

#include "file_utils.h"

#include <xtt.h>

#include <sodium.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef USE_TPM
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_socket.h>
unsigned char tcti_context_buffer_g[128];
#endif

uint32_t key_handle_g = 0x81800000;
uint32_t gpk_handle_g = 0x1400000;
uint32_t cred_handle_g = 0x1400001;
uint32_t root_id_handle_g = 0x1400003;
uint32_t root_pubkey_handle_g = 0x1400004;
const char *tpm_hostname_g = "localhost";
const char *tpm_port_g = "2321";
const char *tpm_password = NULL;
uint16_t tpm_password_len = 0;

xtt_version version_g = XTT_VERSION_ONE;

const char *requested_client_id_file = "requested_client_id.bin";
const char *server_id_file = "server_id.bin";
const char *daa_gpk_file = "daa_gpk.bin";
const char *daa_cred_file = "daa_cred.bin";
const char *daa_secretkey_file = "daa_secretkey.bin";
const char *basename_file = "basename.bin";
const char *root_id_file = "root_id.bin";
const char *root_pubkey_file = "root_pub.bin";

// We have a toy "database" of server certificates
typedef struct {
    xtt_certificate_root_id root_id;
    struct xtt_server_root_certificate_context cert;
} certificate_db_record;
certificate_db_record certificate_db[1];
const size_t certificate_db_size = 1;

void parse_cmd_args(int argc, char *argv[], xtt_suite_spec *suite_spec, char *ip, unsigned short *port, int *use_tpm);

int connect_to_server(const char *ip, unsigned short port);

int initialize_ids(xtt_identity_type *requested_client_id,
                   xtt_identity_type *intended_server_id);

int initialize_certs(int use_tpm);

int initialize_daa(struct xtt_client_group_context *group_ctx, int use_tpm);

#ifdef USE_TPM
int
read_nvram(unsigned char *out,
           uint16_t length,
           TPM_HANDLE index,
           TSS2_TCTI_CONTEXT *tcti_context);
#endif

int do_handshake(int socket,
                 xtt_identity_type *requested_client_id,
                 xtt_identity_type *intended_server_id,
                 struct xtt_client_group_context *group_ctx,
                 struct xtt_client_handshake_context *ctx);

struct xtt_server_root_certificate_context*
lookup_certificate(xtt_certificate_root_id *claimed_root_id);

int report_results(xtt_identity_type *requested_client_id,
                   struct xtt_client_handshake_context *ctx);

int main(int argc, char *argv[])
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;
    int init_daa_ret = -1;
    int socket = -1;

    // 0) Parse the command line args
    xtt_suite_spec suite_spec;
    char server_ip[16];
    unsigned short server_port;
    int use_tpm;
    parse_cmd_args(argc, argv, &suite_spec, server_ip, &server_port, &use_tpm);

    // 1) Set my requested id and the intended server id (from files).
    xtt_identity_type requested_client_id;
    xtt_identity_type intended_server_id;
    int id_ret = initialize_ids(&requested_client_id, &intended_server_id);
    if(0 != id_ret) {
        fprintf(stderr, "Error setting XTT ID's!\n");
        goto finish;
    }

    // 2) Setup the needed XTT contexts (from files).
    struct xtt_client_group_context group_ctx;
    init_daa_ret = initialize_daa(&group_ctx, use_tpm);
    if (0 != init_daa_ret) {
        fprintf(stderr, "Error initializing DAA context\n");
        goto finish;
    }
    int init_certs_ret = initialize_certs(use_tpm);
    if (0 != init_certs_ret) {
        fprintf(stderr, "Error initializing server/root certificate contexts\n");
        goto finish;
    }

    // 3) Make TCP connection to server.
    printf("Connecting to server at %s:%d ...\t", server_ip, server_port);
    socket = connect_to_server(server_ip, server_port);
    if (socket < 0)
        goto finish;
    printf("ok\n");

    // 4) Initialize XTT handshake context
    // (will be populated with useful information after a successful handshake).
    printf("Using suite_spec = %d\n", suite_spec);
    unsigned char in_buffer[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
    unsigned char out_buffer[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
    struct xtt_client_handshake_context ctx;
    rc = xtt_initialize_client_handshake_context(&ctx, in_buffer, sizeof(in_buffer), out_buffer, sizeof(out_buffer), version_g, suite_spec);
    if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error initializing client handshake context: %d\n", rc);
        goto finish;
    }

    // 5) Run the identity-provisioning handshake with the server.
    int handshake_ret;
    handshake_ret = do_handshake(socket,
                                 &requested_client_id,
                                 &intended_server_id,
                                 &group_ctx,
                                 &ctx);
    if (0 == handshake_ret) {
        // 6) Print the results (what we and the server now agree on post-handshake)
        int report_ret;
        report_ret = report_results(&requested_client_id,
                                    &ctx);
        if (0 != report_ret)
            goto finish;
    } else {
        fprintf(stderr, "Handshake failed!\n");
        goto finish;
    }

finish:
    if (socket > 0)
        close(socket);
#ifdef USE_TPM
    if (use_tpm && 0==init_daa_ret)
        tss2_tcti_finalize((TSS2_TCTI_CONTEXT*)tcti_context_buffer_g);
#endif
    if (XTT_RETURN_SUCCESS == rc) {
        return 0;
    } else {
        return 1;
    }
}

void parse_cmd_args(int argc, char *argv[], xtt_suite_spec *suite_spec, char *ip, unsigned short *port, int *use_tpm)
{
    if (5 != argc && 4 != argc) {
        fprintf(stderr, "usage: %s <suite_spec> <server IP> <server port> [--use-tpm]\n", argv[0]);
        fprintf(stderr, "\twhere:\n");
        fprintf(stderr, "\t\tXTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512    = 1,\n");
        fprintf(stderr, "\t\tXTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B   = 2,\n");
        fprintf(stderr, "\t\tXTT_X25519_LRSW_ED25519_AES256GCM_SHA512           = 3,\n");
        fprintf(stderr, "\t\tXTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B          = 4,\n");
        exit(1);
    }

    *suite_spec = atoi(argv[1]);
    if (*suite_spec != 1 && *suite_spec != 2 && *suite_spec != 3 && *suite_spec != 4) {
        fprintf(stderr, "Unknown suite_spec\n");
        exit(1);
    }

    strcpy(ip, argv[2]);
    *port = atoi(argv[3]);

    *use_tpm = 0;
    if (5 == argc) {
        if (0 == strcmp("--use-tpm", argv[4])) {
            *use_tpm = 1;
        } else {
            fprintf(stderr, "Unknown tpm option: %s\n", argv[4]);
            exit(1);
        }
    }
}

int connect_to_server(const char *ip, unsigned short port)
{
    int sock_ret = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ret == -1) {
        fprintf(stderr, "Error opening client socket\n");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (connect(sock_ret, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error connecting to server\n");
        close(sock_ret);
        return -1;
    }

    return sock_ret;
}

int initialize_ids(xtt_identity_type *requested_client_id,
                   xtt_identity_type *intended_server_id)
{
    int read_ret;

    // 1) Set requested client id from file
    char requested_client_id_str[sizeof(xtt_identity_type)];
    read_ret = read_file_into_buffer((unsigned char*)requested_client_id_str, sizeof(xtt_identity_type), requested_client_id_file);
    if (sizeof(xtt_identity_type) != read_ret && 1 != read_ret) {
        fprintf(stderr, "Error reading requested client ID from file\n");
        return -1;
    }
    if (0 == memcmp(requested_client_id_str, "0", read_ret)) {
        *requested_client_id = xtt_null_identity;
    } else {
        memcpy(requested_client_id->data, requested_client_id_str, sizeof(xtt_identity_type));
    }

    // Set server's id from file
    char intended_server_id_str[sizeof(xtt_identity_type)];
    read_ret = read_file_into_buffer((unsigned char*)intended_server_id_str, sizeof(xtt_identity_type), server_id_file);
    if (sizeof(xtt_identity_type) != read_ret) {
        fprintf(stderr, "Error reading server's ID from file\n");
        return -1;
    }
    memcpy(intended_server_id->data, intended_server_id_str, sizeof(xtt_identity_type));

    return 0;
}

int initialize_daa(struct xtt_client_group_context *group_ctx, int use_tpm)
{
    (void)write_buffer_to_file;
    xtt_return_code_type rc;
    int read_ret;

    // 1) Read DAA-related things in from file/TPM-NVRAM
    unsigned char basename[1024];
    read_ret = read_file_into_buffer(basename, sizeof(basename), basename_file);
    if (read_ret < 0) {
        fprintf(stderr, "Error reading basename from file\n");
        return -1;
    }
    uint16_t basename_len = (uint16_t)read_ret;

#ifdef USE_TPM
    TSS2_TCTI_CONTEXT *tcti_context;
    if (use_tpm) {
        size_t tcti_context_size = tss2_tcti_getsize_socket();
        assert(tcti_context_size < sizeof(tcti_context_buffer_g));
        tcti_context = (TSS2_TCTI_CONTEXT*)tcti_context_buffer_g;
        int tcti_ret = tss2_tcti_init_socket(tpm_hostname_g, tpm_port_g, tcti_context);
        if (TSS2_RC_SUCCESS != tcti_ret) {
            fprintf(stderr, "Error: Unable to initialize TCTI context\n");
            return -1;
        }
    }
#endif

    xtt_daa_group_pub_key_lrsw gpk;
    xtt_daa_credential_lrsw cred;
    xtt_daa_priv_key_lrsw daa_priv_key;
    if (use_tpm) {
#ifdef USE_TPM
        int nvram_ret;
        nvram_ret = read_nvram(gpk.data,
                               sizeof(xtt_daa_group_pub_key_lrsw),
                               gpk_handle_g,
                               tcti_context);
        if (0 != nvram_ret) {
            fprintf(stderr, "Error reading GPK from TPM NVRAM");
            return -1;
        }

        nvram_ret = read_nvram(cred.data,
                               sizeof(xtt_daa_credential_lrsw),
                               cred_handle_g,
                               tcti_context);
        if (0 != nvram_ret) {
            fprintf(stderr, "Error reading credential from TPM NVRAM");
            return -1;
        }
#else
        fprintf(stderr, "Attempted to use a TPM, but not built with TPM enabled!\n");
        return -1;
#endif
    } else {
        read_ret = read_file_into_buffer(gpk.data, sizeof(xtt_daa_group_pub_key_lrsw), daa_gpk_file);
        if (sizeof(xtt_daa_group_pub_key_lrsw) != read_ret) {
            fprintf(stderr, "Error reading DAA GPK from file\n");
            return -1;
        }

        read_ret = read_file_into_buffer(cred.data, sizeof(xtt_daa_credential_lrsw), daa_cred_file);
        if (sizeof(xtt_daa_credential_lrsw) != read_ret) {
            fprintf(stderr, "Error reading DAA credential from file\n");
            return -1;
        }

        read_ret = read_file_into_buffer(daa_priv_key.data, sizeof(xtt_daa_priv_key_lrsw), daa_secretkey_file);
        if (sizeof(xtt_daa_priv_key_lrsw) != read_ret) {
            fprintf(stderr, "Error reading DAA secret-key from file\n");
            return -1;
        }
    }

    // 2) Generate gid from gpk (gid = SHA-256(gpk))
    xtt_group_id gid;
    int hash_ret = crypto_hash_sha256(gid.data, gpk.data, sizeof(gpk));
    if (0 != hash_ret)
        return -1;

    // 3) Initialize DAA context using the above information
    if (use_tpm) {
#ifdef USE_TPM
        rc = xtt_initialize_client_group_context_lrswTPM(group_ctx,
                                                         &gid,
                                                         &cred,
                                                         (unsigned char*)basename,
                                                         basename_len,
                                                         key_handle_g,
                                                         tpm_password,
                                                         tpm_password_len,
                                                         tcti_context);
#else
        fprintf(stderr, "Attempted to use a TPM, but not built with TPM enabled!\n");
        return -1;
#endif
    } else {
        rc = xtt_initialize_client_group_context_lrsw(group_ctx,
                                             &gid,
                                             &daa_priv_key,
                                             &cred,
                                             (unsigned char*)basename,
                                             basename_len);
    }

    if (XTT_RETURN_SUCCESS != rc)
        return -1;

    return 0;
}

int initialize_certs(int use_tpm)
{
    (void)write_buffer_to_file;
    xtt_return_code_type rc;
    int read_ret;

#ifdef USE_TPM
    // We assume initialize_daa() has already been called, so TCTI has been initialized
    TSS2_TCTI_CONTEXT *tcti_context = (TSS2_TCTI_CONTEXT*)tcti_context_buffer_g;
#endif

    // 1) Read root cert stuff in from file
    xtt_certificate_root_id root_id;
    xtt_ed25519_pub_key root_public_key;
    if (use_tpm) {
#ifdef USE_TPM
        int nvram_ret;
        nvram_ret = read_nvram(root_id.data,
                               sizeof(xtt_certificate_root_id),
                               root_id_handle_g,
                               tcti_context);
        if (0 != nvram_ret) {
            fprintf(stderr, "Error reading root ID from TPM NVRAM");
            return -1;
        }

        nvram_ret = read_nvram(root_public_key.data,
                               sizeof(xtt_ed25519_pub_key),
                               root_pubkey_handle_g,
                               tcti_context);
        if (0 != nvram_ret) {
            fprintf(stderr, "Error reading root's public key from TPM NVRAM");
            return -1;
        }
#else
        fprintf(stderr, "Attempted to use a TPM, but not built with TPM enabled!\n");
        return -1;
#endif
    } else {
        read_ret = read_file_into_buffer(root_id.data, sizeof(xtt_certificate_root_id), root_id_file);
        if (sizeof(xtt_certificate_root_id) != read_ret) {
            fprintf(stderr, "Error reading root's id from file\n");
            return -1;
        }
        read_ret = read_file_into_buffer(root_public_key.data, sizeof(xtt_ed25519_pub_key), root_pubkey_file);
        if (sizeof(xtt_ed25519_pub_key) != read_ret) {
            fprintf(stderr, "Error reading root's public key from file\n");
            return -1;
        }
    }

    // 2) Initialize root_certificate_db
    memcpy(certificate_db[0].root_id.data,
           root_id.data,
           sizeof(xtt_certificate_root_id));
    rc = xtt_initialize_server_root_certificate_context_ed25519(&certificate_db[0].cert,
                                                                &root_id,
                                                                &root_public_key);
    if (XTT_RETURN_SUCCESS != rc)
        return -1;

    return 0;
}

int do_handshake(int socket,
                 xtt_identity_type *requested_client_id,
                 xtt_identity_type *intended_server_id,
                 struct xtt_client_group_context *group_ctx,
                 struct xtt_client_handshake_context *ctx)
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;

    uint16_t bytes_requested = 0;
    unsigned char *io_ptr = NULL;
    xtt_certificate_root_id claimed_root_id;
    printf("Starting identity-provisioning handshake, by sending ClientInit message...\n");
    rc = xtt_handshake_client_start(&bytes_requested,
                                    &io_ptr,
                                    ctx);
    while (XTT_RETURN_HANDSHAKE_FINISHED != rc) {
        switch (rc) {
            case XTT_RETURN_WANT_WRITE:
                {
                    printf("Writing %d bytes...", bytes_requested);
                    int write_ret = write(socket, io_ptr, bytes_requested);
                    if (write_ret <= 0) {
                        fprintf(stderr, "Error sending to server\n");
                        return -1;
                    }
                    printf("wrote %d bytes\n", write_ret);

                    rc = xtt_handshake_client_handle_io((uint16_t)write_ret,
                                                        0,  // 0 bytes read
                                                        &bytes_requested,
                                                        &io_ptr,
                                                        ctx);

                    break;
                }
            case XTT_RETURN_WANT_READ:
                {
                    printf("Reading %d bytes...", bytes_requested);
                    int read_ret = read(socket, io_ptr, bytes_requested);
                    if (read_ret <= 0) {
                        fprintf(stderr, "Error receiving from server\n");
                        return -1;
                    }

                    rc = xtt_handshake_client_handle_io(0,  // 0 bytes written
                                                        (uint16_t)read_ret,
                                                        &bytes_requested,
                                                        &io_ptr,
                                                        ctx);
                    printf("read %d bytes\n", read_ret);

                    break;
                }
            case XTT_RETURN_WANT_PREPARSESERVERATTEST:
                {
                    printf("Received ServerInitAndAttest. Pre-parsing it to find the root_id claimed by the server...\n");

                    rc = xtt_handshake_client_preparse_serverattest(&claimed_root_id,
                                                                    &bytes_requested,
                                                                    &io_ptr,
                                                                    ctx);

                    break;
                }
            case XTT_RETURN_WANT_BUILDIDCLIENTATTEST:
                {
                    printf("Looking up server's certificate from its claimed root_id...\n");

                    struct xtt_server_root_certificate_context *server_cert;
                    server_cert = lookup_certificate(&claimed_root_id);
                    if (NULL == server_cert) {
                        unsigned char err_buffer[16];
                        (void)build_error_msg(err_buffer, &bytes_requested, version_g);
                        int write_ret = write(socket, err_buffer, bytes_requested);
                        if (write_ret > 0) {
                        }
                        return -1;
                    }

                    printf("Checking server's signature, then building Identity_ClientAttest...\n");

                    rc = xtt_handshake_client_build_idclientattest(&bytes_requested,
                                                                   &io_ptr,
                                                                   server_cert,
                                                                   requested_client_id,
                                                                   intended_server_id,
                                                                   group_ctx,
                                                                   ctx);

                    break;
                }
            case XTT_RETURN_WANT_PARSEIDSERVERFINISHED:
                {
                    printf("Received Identity_ServerFinished. Parsing it...\n");

                    rc = xtt_handshake_client_parse_idserverfinished(&bytes_requested,
                                                                     &io_ptr,
                                                                     ctx);
                    break;
                }
            case XTT_RETURN_HANDSHAKE_FINISHED:
                break;
            case XTT_RETURN_RECEIVED_ERROR_MSG:
                fprintf(stderr, "Received error message from server\n");
                return -1;
            default:
                printf("Encountered error during client handshake: %d\n", rc);
                // Send error message
                (void)write(socket, io_ptr, bytes_requested);
                return -1;
        }
    }

    if (XTT_RETURN_HANDSHAKE_FINISHED == rc) {
        printf("Handshake completed successfully!\n");
        return 0;
    } else {
        return -1;
    }
}

struct xtt_server_root_certificate_context*
lookup_certificate(xtt_certificate_root_id *claimed_root_id)
{
    // 1) See if we can find the claimed root_id
    certificate_db_record *found_cert = NULL;
    for (size_t i=0; i < certificate_db_size; ++i) {
        int cmp_ret = xtt_crypto_memcmp(certificate_db[i].root_id.data,
                                        claimed_root_id->data,
                                        sizeof(xtt_certificate_root_id));
        if (0 == cmp_ret) {
            found_cert = &certificate_db[i];
            break;
        }
    }

    char claimed_root_id_str[17];
    assert(sizeof(claimed_root_id_str) == (sizeof(xtt_certificate_root_id) + 1));
    memcpy(claimed_root_id_str, claimed_root_id->data, sizeof(xtt_certificate_root_id));
    claimed_root_id_str[sizeof(xtt_certificate_root_id)] = 0;
    printf("Server claimed root_id=%s...\t", claimed_root_id_str);
    if (NULL != found_cert) {
        printf("which matches the root id we have!\n");
    } else {
        printf("which does NOT match the root id we have!\nQuitting...\n");
        return NULL;
    }

    return &found_cert->cert;
}

int report_results(xtt_identity_type *requested_client_id,
                   struct xtt_client_handshake_context *ctx)
{
    xtt_identity_type my_assigned_id;
    if (XTT_RETURN_SUCCESS != xtt_get_my_identity(&my_assigned_id, ctx)) {
        printf("Error getting my assigned client id!\n");
        return 1;
    }
    printf("Server assigned me id: {");
    for (size_t i=0; i < sizeof(xtt_identity_type); ++i) {
        printf("%#02X", my_assigned_id.data[i]);
        if (i < (sizeof(xtt_identity_type)-1)) {
            printf(", ");
        } else {
            printf("}\n");
        }
    }
    if (0 != xtt_crypto_memcmp(xtt_null_identity.data, requested_client_id->data, sizeof(xtt_identity_type))) {
        printf("(I requested id: {");
        for (size_t i=0; i < sizeof(xtt_identity_type); ++i) {
            printf("%#02X", requested_client_id->data[i]);
            if (i < (sizeof(xtt_identity_type)-1)) {
                printf(", ");
            } else {
                printf("}\n");
            }
        }
    }

    xtt_ed25519_pub_key my_longterm_key;
    if (XTT_RETURN_SUCCESS != xtt_get_my_longterm_key_ed25519(&my_longterm_key, ctx)) {
        printf("Error getting my longterm key!\n");
        return 1;
    }
    printf("My longterm key: {");
    for (size_t i=0; i < sizeof(xtt_ed25519_pub_key); ++i) {
        printf("%#02X", my_longterm_key.data[i]);
        if (i < (sizeof(xtt_ed25519_pub_key)-1)) {
            printf(", ");
        } else {
            printf("}\n");
        }
    }

    xtt_daa_pseudonym_lrsw my_pseudonym;
    if (XTT_RETURN_SUCCESS != xtt_get_my_pseudonym_lrsw(&my_pseudonym, ctx)) {
        printf("Error getting my pseudonym!\n");
        return 1;
    }
    printf("I have pseudonym: {");
    for (size_t i=0; i < sizeof(xtt_daa_pseudonym_lrsw); ++i) {
        printf("%#02X", my_pseudonym.data[i]);
        if (i < (sizeof(xtt_daa_pseudonym_lrsw)-1)) {
            printf(", ");
        } else {
            printf("}\n");
        }
    }

    return 0;
}

#ifdef USE_TPM
int
read_nvram(unsigned char *out,
           uint16_t size,
           TPM_HANDLE index,
           TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    TSS2_SYS_CONTEXT *sapi_context = malloc(sapi_ctx_size);
    if (NULL == sapi_context) {
        fprintf(stderr, "Error allocating memory for TPM SAPI context\n");
        return -1;
    }

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    ret = Tss2_Sys_Initialize(sapi_context,
                              sapi_ctx_size,
                              tcti_context,
                              &abi_version);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing TPM SAPI context\n");
        goto finish;
    }

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

    while (size > 0) {
        uint16_t bytes_to_read = size;

        TPM2B_MAX_NV_BUFFER nv_data = {.size=0};

        ret = Tss2_Sys_NV_Read(sapi_context,
                               index,
                               index,
                               &sessionsData,
                               bytes_to_read,
                               data_offset,
                               &nv_data,
                               &sessionsDataOut);

        if (ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error reading from NVRAM\n");
            goto finish;
        }

        size -= nv_data.size;

        memcpy(out + data_offset, nv_data.buffer, nv_data.size);
        data_offset += nv_data.size;
    }

finish:
    Tss2_Sys_Finalize(sapi_context);
    free(sapi_context);

    if (ret == TSS2_RC_SUCCESS) {
        return 0;
    } else {
        return -1;
    }
}
#endif
