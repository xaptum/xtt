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

#define _POSIX_C_SOURCE 200112L
#include "client.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <xtt/crypto_types.h>
#include <xtt/crypto_wrapper.h>
#include <xtt/context.h>
#include <xtt/messages.h>
#include <xtt/util/util_errors.h>
#include <xtt/util/file_io.h>
#include <xtt/util/asn1.h>
#include <xtt/util/root.h>
#include <xtt/util/tpm_context.h>
#include <xtt/tpm/handles.h>
#include <xtt/tpm/nvram.h>

#ifdef USE_TPM
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_socket.h>
#include <tss2/tss2_tcti_device.h>
#endif

const size_t tpm_devfile_length_g = 9;
const char *tpm_password = NULL;
uint16_t tpm_password_len = 0;

xtt_version version_g_client = XTT_VERSION_ONE;

char* stored_root_id[sizeof(xtt_certificate_root_id)];
struct xtt_server_root_certificate_context stored_cert;

static int connect_to_server(const char *ip, char *port);

static int initialize_certs(xtt_root_certificate* root_certificate);

static int initialize_daa(struct xtt_client_group_context *group_ctx,
                unsigned char* basename,
                uint16_t basename_len,
                xtt_daa_group_pub_key_lrsw* gpk,
                xtt_daa_credential_lrsw* cred,
                xtt_daa_priv_key_lrsw* daa_priv_key,
                int use_tpm,
                TSS2_TCTI_CONTEXT* tcti_context);

static int read_in_from_TPM(TSS2_TCTI_CONTEXT* tcti_context,
                  unsigned char* basename,
                  uint16_t* basename_len,
                  xtt_daa_group_pub_key_lrsw* gpk,
                  xtt_daa_credential_lrsw* cred,
                  xtt_root_certificate* root_certificate);

static int read_in_from_files(unsigned char* basename,
                       uint16_t* basename_len,
                       const char* basename_file,
                       xtt_daa_group_pub_key_lrsw* gpk,
                       const char* daa_gpk_file,
                       xtt_daa_credential_lrsw* cred,
                       const char* daa_cred_file,
                       xtt_daa_priv_key_lrsw* daa_priv_key,
                       const char* daa_secretkey_file,
                       xtt_root_certificate* root_certificate,
                       const char* root_cert_file);

static int do_handshake_client(int socket,
                 xtt_identity_type *requested_client_id,
                 struct xtt_client_group_context *group_ctx,
                 struct xtt_client_handshake_context *ctx);

static struct xtt_server_root_certificate_context*
lookup_certificate(xtt_certificate_root_id *claimed_root_id);

static int report_results_client(xtt_identity_type *requested_client_id,
                   struct xtt_client_handshake_context *ctx,
                   const char* assigned_client_id_out_file,
                   const char* longterm_public_key_out_file,
                   const char* longterm_private_key_out_file);

int run_client(struct cli_params* params)
{
    const char *requested_client_id_file = params->requestid;
    const char *daa_gpk_file = params->daagpk;
    const char *daa_cred_file = params->daacred;
    const char *daa_secretkey_file = params->daasecretkey;
    const char *basename_file = params->basename;
    const char *root_cert_file = params->rootcert;
    const char *assigned_client_id_out_file = params->assignedid;
    const char *longterm_public_key_out_file = params->longtermcert;
    const char *longterm_private_key_out_file = params->longtermpriv;
    const char *server_ip = params->serverhost;
    const char *server_port = params->portstr;
    int use_tpm = params->usetpm;
    const char *tcti_dev_file = params->devfile;

    int init_daa_ret = -1;
    int socket = -1;

    int ret = 0;
    int read_ret = 0;

    ret = xtt_crypto_initialize_crypto();
    if (0 != ret) {
        fprintf(stderr, "Error initializing cryptography library: %d\n", ret);
        return 1;
    }
    setbuf(stdout, NULL);

    //Read in requested client id, setting it to xtt_null_identity if no client ID is provided
    xtt_identity_type requested_client_id = {.data = {0}};
    if(NULL == params->requestid){
        requested_client_id = xtt_null_identity;
    }else{
        read_ret = xtt_read_from_file(requested_client_id_file, requested_client_id.data, sizeof(xtt_identity_type));
        if (read_ret < 0) {
            return READ_FROM_FILE_ERROR;
        }
    }

    //Set suite spec from command line args
    xtt_suite_spec suite_spec = 0;
    if (0 == strcmp(params->suitespec, "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512")) {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512;
    } else if (0 == strcmp(params->suitespec, "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B")) {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B;
    } else if (0 == strcmp(params->suitespec, "X25519_LRSW_ECDSAP256_AES256GCM_SHA512")) {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512;
    } else if (0 == strcmp(params->suitespec, "X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B")) {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B;
    } else {
        fprintf(stderr, "Unknown suite_spec '%s'\n", params->suitespec);
        exit(1);
    }

    //Set TCTI from command line args
    xtt_tcti_type tcti_type;
    if (0 == strcmp(params->tcti, "device")) {
        tcti_type = XTT_TCTI_DEVICE;
    } else if (0 == strcmp(params->tcti, "socket")) {
        tcti_type = XTT_TCTI_SOCKET;
    } else {
        fprintf(stderr, "Unknown tcti_type '%s'\n", params->tcti);
        exit(1);
    }

    //Set TCTI device file from command line args
    if(use_tpm && tcti_type == XTT_TCTI_DEVICE)
    {
        if(NULL == params->devfile){
            printf("Not given a device file for TCTI \n");
            exit(1);
        } else
        {
            tcti_dev_file = params->devfile;
        }
    }

    // 1) Setup the needed XTT contexts (from files/TPM).
    // 1i) Setup TPM TCTI, if using TPM
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
#ifdef USE_TPM
    int init_tcti_ret = 0;
    if (use_tpm) {
        init_tcti_ret = initialize_tcti(&tcti_context, tcti_type, tcti_dev_file);
        if (0 != init_tcti_ret) {
            fprintf(stderr, "Error initializing TPM TCTI context\n");
            goto finish;
        }
    }
#endif

    xtt_daa_group_pub_key_lrsw gpk = {.data = {0}};
    xtt_daa_credential_lrsw cred = {.data = {0}};
    xtt_daa_priv_key_lrsw daa_priv_key = {.data = {0}};
    xtt_root_certificate root_certificate = {.data = {0}};
    unsigned char basename[1024] = {0};
    uint16_t basename_len = sizeof(basename);

    //Read in DAA data from the TPM or from files
    if (use_tpm) {
        read_ret = read_in_from_TPM(tcti_context, basename, &basename_len, &gpk, &cred, &root_certificate);
    } else {
        read_ret = read_in_from_files(basename, &basename_len, basename_file,
                                      &gpk, daa_gpk_file,
                                      &cred, daa_cred_file,
                                      &daa_priv_key, daa_secretkey_file,
                                      &root_certificate, root_cert_file);
    }
    if (read_ret != 0) {
        return READ_FROM_FILE_ERROR;
    }


    // 1ii) Initialize DAA
    struct xtt_client_group_context group_ctx;
    init_daa_ret = initialize_daa(&group_ctx, basename, basename_len, &gpk, &cred, &daa_priv_key, use_tpm, tcti_context);
    ret = init_daa_ret;
    if (0 != init_daa_ret) {
        fprintf(stderr, "Error initializing DAA context\n");
        goto finish;
    }
    // 1iii) Initialize Certificates
    ret = initialize_certs(&root_certificate);
    if (0 != ret) {
        fprintf(stderr, "Error initializing server/root certificate contexts\n");
        goto finish;
    }

    // 2) Make TCP connection to server.
    printf("Connecting to server at %s:%s ...\t", server_ip, server_port);
    socket = connect_to_server(server_ip, (char*)server_port);
    if (socket < 0) {
        ret = 1;
        goto finish;
    }
    printf("ok\n");

    // 3) Initialize XTT handshake context
    // (will be populated with useful information after a successful handshake).
    printf("Using suite_spec = %d\n", suite_spec);
    unsigned char in_buffer[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH] = {0};
    unsigned char out_buffer[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH] = {0};
    struct xtt_client_handshake_context ctx;
    xtt_return_code_type rc = xtt_initialize_client_handshake_context(&ctx, in_buffer, sizeof(in_buffer), out_buffer, sizeof(out_buffer), version_g_client, suite_spec);
    if (XTT_RETURN_SUCCESS != rc) {
        ret = 1;
        fprintf(stderr, "Error initializing client handshake context: %d\n", rc);
        goto finish;
    }

    // 4) Run the identity-provisioning handshake with the server.
    ret = do_handshake_client(socket,
                       &requested_client_id,
                       &group_ctx,
                       &ctx);
    if (0 == ret) {
    // 5) Print the results (what we and the server now agree on post-handshake)
        ret = report_results_client(&requested_client_id,
                             &ctx, assigned_client_id_out_file, longterm_public_key_out_file, longterm_private_key_out_file);
        if (0 != ret)
            goto finish;
    } else {
        fprintf(stderr, "Handshake failed!\n");
        goto finish;
    }

finish:
    if (socket > 0)
        close(socket);
#ifdef USE_TPM
    if (use_tpm && 0==init_tcti_ret) {
        tss2_tcti_finalize(tcti_context);
    }
#endif
    if (0 == ret) {
        return 0;
    } else {
        return 1;
    }
}


static
int connect_to_server(const char *server_host, char *port)
{
    struct addrinfo *serverinfo;
    struct addrinfo hints = {.ai_protocol = IPPROTO_TCP};

    if (0 != getaddrinfo(server_host, port, &hints, &serverinfo)) {
        fprintf(stderr, "Error resolving server host '%s:%s'\n", server_host, port);
        return -1;
    }

    struct addrinfo *addr = NULL;
    int sock_ret = -1;
    for (addr=serverinfo; addr!=NULL; addr=addr->ai_next) {
        sock_ret = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol);
        if (sock_ret == -1) {
            fprintf(stderr, "Error opening client socket, trying next address\n");
            continue;
        }

        if (connect(sock_ret, addr->ai_addr, addr->ai_addrlen) < 0) {
            fprintf(stderr, "Error connecting to server, trying next address\n");
            close(sock_ret);
            continue;
        }

        break;
    }

    freeaddrinfo(serverinfo);

    if (NULL == addr) {
        fprintf(stderr, "Unable to connect to server\n");
        return -1;
    }

    return sock_ret;
}

static
int read_in_from_TPM(TSS2_TCTI_CONTEXT* tcti_context,
                  unsigned char* basename,
                  uint16_t* basename_len,
                  xtt_daa_group_pub_key_lrsw* gpk,
                  xtt_daa_credential_lrsw* cred,
                  xtt_root_certificate* root_certificate
                  )
{
#ifdef USE_TPM
    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    TSS2_SYS_CONTEXT *sapi_context = malloc(sapi_ctx_size);
    uint16_t length_read = 0;
    int nvram_ret = 0;
    nvram_ret = initialize_sapi(sapi_context, sapi_ctx_size, tcti_context);
    if (0 != nvram_ret) {
        fprintf(stderr, "Error creating SAPI context\n");
        goto finish;
    }

    nvram_ret = xtt_read_object(basename,
                               *basename_len,
                               &length_read,
                               XTT_BASENAME,
                               sapi_context);
    if (0 != nvram_ret) {
        fprintf(stderr, "Error reading basename from TPM NVRAM\n");
        goto finish;
    }
    *basename_len = length_read;

    length_read = 0;
    nvram_ret = xtt_read_object(gpk->data,
                                sizeof(xtt_daa_group_pub_key_lrsw),
                                &length_read,
                                XTT_GROUP_PUBLIC_KEY,
                                sapi_context);
    if (0 != nvram_ret) {
        fprintf(stderr, "Error reading GPK from TPM NVRAM");
        nvram_ret = TPM_ERROR;
        goto finish;
    }

    length_read = 0;
    nvram_ret = xtt_read_object(cred->data,
                                sizeof(xtt_daa_credential_lrsw),
                                &length_read,
                                XTT_CREDENTIAL,
                                sapi_context);
    if (0 != nvram_ret) {
        fprintf(stderr, "Error reading credential from TPM NVRAM");
        nvram_ret = TPM_ERROR;
        goto finish;
    }

    length_read = 0;
    nvram_ret = xtt_read_object(root_certificate->data,
                                sizeof(xtt_root_certificate),
                                &length_read,
                                XTT_ROOT_XTT_CERTIFICATE,
                                sapi_context);
    if (0 != nvram_ret) {
        fprintf(stderr, "Error reading root's certificate from TPM NVRAM");
        nvram_ret = TPM_ERROR;
        goto finish;
    }

finish:
    free(sapi_context);
    return nvram_ret;
#else
    fprintf(stderr, "Attempted to use a TPM, but not built with TPM enabled!\n");
    return TPM_ERROR;
#endif
}

static
int read_in_from_files(unsigned char* basename,
                       uint16_t* basename_len,
                       const char* basename_file,
                       xtt_daa_group_pub_key_lrsw* gpk,
                       const char* daa_gpk_file,
                       xtt_daa_credential_lrsw* cred,
                       const char* daa_cred_file,
                       xtt_daa_priv_key_lrsw* daa_priv_key,
                       const char* daa_secretkey_file,
                       xtt_root_certificate* root_certificate,
                       const char* root_cert_file)
{
    int read_ret = xtt_read_from_file(basename_file, basename, sizeof(basename));
    if (read_ret < 0) {
        return READ_FROM_FILE_ERROR;
    }
    *basename_len = (uint16_t)read_ret;

    read_ret = xtt_read_from_file(daa_gpk_file, gpk->data, sizeof(xtt_daa_group_pub_key_lrsw));
    if (read_ret < 0) {
        return READ_FROM_FILE_ERROR;
    }

    read_ret = xtt_read_from_file(daa_cred_file, cred->data, sizeof(xtt_daa_credential_lrsw));
    if (read_ret < 0) {
        return READ_FROM_FILE_ERROR;
    }

    read_ret = xtt_read_from_file(daa_secretkey_file, daa_priv_key->data, sizeof(xtt_daa_priv_key_lrsw));
    if (read_ret < 0) {
        return READ_FROM_FILE_ERROR;
    }

    read_ret = xtt_read_from_file(root_cert_file, root_certificate->data, sizeof(xtt_root_certificate));
    if (read_ret < 0) {
        return READ_FROM_FILE_ERROR;
    }

    return 0;
}

static
int initialize_daa(struct xtt_client_group_context *group_ctx,
                   unsigned char* basename,
                   uint16_t basename_len,
                   xtt_daa_group_pub_key_lrsw* gpk,
                   xtt_daa_credential_lrsw* cred,
                   xtt_daa_priv_key_lrsw* daa_priv_key,
                   int use_tpm,
                   TSS2_TCTI_CONTEXT* tcti_context)
{
    xtt_return_code_type rc = 0;

    // 1) Generate gid from gpk (gid = SHA-256(gpk | basename))
    xtt_group_id gid = {.data = {0}};

    crypto_hash_sha256_state hash_state;
    int hash_ret = crypto_hash_sha256_init(&hash_state);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_update(&hash_state, gpk->data, sizeof(*gpk));
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_update(&hash_state, basename, basename_len);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_final(&hash_state, gid.data);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;

    // 2) Initialize DAA context using the above information
    if (use_tpm) {
#ifdef USE_TPM
        rc = xtt_initialize_client_group_context_lrswTPM(group_ctx,
                                                         &gid,
                                                         cred,
                                                         basename,
                                                         basename_len,
                                                         XTT_KEY_HANDLE,
                                                         tpm_password,
                                                         tpm_password_len,
                                                         tcti_context);
#else
        fprintf(stderr, "Attempted to use a TPM, but not built with TPM enabled!\n");
        return TPM_ERROR;
#endif
    } else {
        rc = xtt_initialize_client_group_context_lrsw(group_ctx,
                                             &gid,
                                             daa_priv_key,
                                             cred,
                                             basename,
                                             basename_len);
    }

    if (XTT_RETURN_SUCCESS != rc){
        printf("%s", xtt_strerror(rc));
        return TPM_ERROR;
    }

    return 0;
}

static
int initialize_certs(xtt_root_certificate* root_certificate)
{
    xtt_return_code_type rc = 0;
    xtt_certificate_root_id root_id = {.data = {0}};
    xtt_ecdsap256_pub_key root_public_key = {.data = {0}};

    xtt_deserialize_root_certificate(&root_public_key, &root_id, root_certificate);

    // Initialize stored data
    memcpy(stored_root_id, root_id.data, sizeof(xtt_certificate_root_id));

    rc = xtt_initialize_server_root_certificate_context_ecdsap256(&stored_cert,
                                                                &root_id,
                                                                &root_public_key);
    if (XTT_RETURN_SUCCESS != rc)
        return CLIENT_ERROR;

    return 0;
}

static
int do_handshake_client(int socket,
                 xtt_identity_type *requested_client_id,
                 struct xtt_client_group_context *group_ctx,
                 struct xtt_client_handshake_context *ctx)
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;

    uint16_t bytes_requested = 0;
    unsigned char *io_ptr = NULL;
    xtt_certificate_root_id claimed_root_id = {.data = {0}};
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
                        (void)xtt_client_build_error_msg(&bytes_requested, &io_ptr, ctx);
                        int write_ret = write(socket, io_ptr, bytes_requested);
                        if (write_ret > 0) {
                        }
                        return -1;
                    }

                    printf("Checking server's signature, then building Identity_ClientAttest...\n");

                    rc = xtt_handshake_client_build_idclientattest(&bytes_requested,
                                                                   &io_ptr,
                                                                   server_cert,
                                                                   requested_client_id,
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
                printf("Encountered error during client handshake: %s (%d)\n", xtt_strerror(rc), rc);
                unsigned char err_buffer[16];
                (void)xtt_client_build_error_msg(&bytes_requested, &io_ptr, ctx);
                int write_ret = write(socket, err_buffer, bytes_requested);
                if (write_ret > 0) {
                }
                return -1;
        }
    }

    if (XTT_RETURN_HANDSHAKE_FINISHED == rc) {
        printf("Handshake completed successfully!\n");
        return 0;
    } else {
        return CLIENT_ERROR;
    }
}

static
struct xtt_server_root_certificate_context*
lookup_certificate(xtt_certificate_root_id *claimed_root_id)
{
    // 1) See if we can find the claimed root_id

    char *found_cert = NULL;

    if(0 == strncmp((char *)claimed_root_id->data, (char *)stored_root_id, sizeof(xtt_certificate_root_id))){
        found_cert = "found";
    }

    unsigned char claimed_root_id_str[sizeof(xtt_certificate_root_id)+1] = {0};
    memcpy(claimed_root_id_str, claimed_root_id->data, sizeof(xtt_certificate_root_id));
    claimed_root_id_str[sizeof(xtt_certificate_root_id)] = 0;
    printf("Server claimed root_id=");
    for(unsigned int i = 0; i < sizeof(xtt_certificate_root_id); i++){
        printf("%x", claimed_root_id_str[i]);
    }
    printf("... ");
    if (NULL != found_cert) {
        printf("which matches the root id we have!\n");
    } else {
        printf("which does NOT match the root id we have!\nQuitting...\n");
        return NULL;
    }

    return &stored_cert;
}

static
int report_results_client(xtt_identity_type *requested_client_id,
                   struct xtt_client_handshake_context *ctx,
                   const char* assigned_client_id_out_file,
                   const char* longterm_public_key_out_file,
                   const char* longterm_private_key_out_file)
{
    int write_ret = 0;

    // 1) Get assigned ID
    xtt_identity_type my_assigned_id = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_my_identity(&my_assigned_id, ctx)) {
        printf("Error getting my assigned client id!\n");
        return 1;
    }
    xtt_identity_string my_assigned_id_as_string = {.data = {0}};
    int convert_ret = xtt_identity_to_string(&my_assigned_id, &my_assigned_id_as_string);
    if (0 != convert_ret) {
        fprintf(stderr, "Error converting assigned id to string\n");
        return 1;
    }
    printf("Server assigned me id: %s\n", my_assigned_id_as_string.data);
    write_ret = xtt_save_to_file((unsigned char*)my_assigned_id_as_string.data, sizeof(xtt_identity_string), assigned_client_id_out_file);
    if(write_ret < 0) {
        return SAVE_TO_FILE_ERROR;
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

    // 2) Get longterm keypair
    xtt_ecdsap256_pub_key my_longterm_key = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_my_longterm_key_ecdsap256(&my_longterm_key, ctx)) {
        printf("Error getting my longterm key!\n");
        return 1;
    }
    printf("My longterm key: {");
    for (size_t i=0; i < sizeof(xtt_ecdsap256_pub_key); ++i) {
        printf("%#02X", my_longterm_key.data[i]);
        if (i < (sizeof(xtt_ecdsap256_pub_key)-1)) {
            printf(", ");
        } else {
            printf("}\n");
        }
    }
    xtt_ecdsap256_priv_key my_longterm_private_key = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_my_longterm_private_key_ecdsap256(&my_longterm_private_key, ctx)) {
        printf("Error getting my longterm private key!\n");
        return 1;
    }

    // 3) Save longterm keypair as X509 certificate and ASN.1-encoded private key
    unsigned char cert_buf[XTT_X509_CERTIFICATE_LENGTH] = {0};
    if (0 != xtt_x509_from_ecdsap256_keypair(&my_longterm_key, &my_longterm_private_key, &my_assigned_id, cert_buf, sizeof(cert_buf))) {
        fprintf(stderr, "Error creating X509 certificate\n");
        return CERT_CREATION_ERROR;
    }
    write_ret = xtt_save_to_file(cert_buf, sizeof(cert_buf), longterm_public_key_out_file);
    if(write_ret < 0){
        return SAVE_TO_FILE_ERROR;
    }

    unsigned char asn1_priv_buf[XTT_ASN1_PRIVATE_KEY_LENGTH] = {0};
    if (0 != xtt_asn1_from_ecdsap256_private_key(&my_longterm_private_key, &my_longterm_key, asn1_priv_buf, sizeof(asn1_priv_buf))) {
        fprintf(stderr, "Error creating ASN.1 private key\n");
        return 1;
    }
    write_ret = xtt_save_to_file(asn1_priv_buf, sizeof(asn1_priv_buf), longterm_private_key_out_file);
    if(write_ret < 0) {
        return SAVE_TO_FILE_ERROR;
    }

    // 4) Get pseudonym
    xtt_daa_pseudonym_lrsw my_pseudonym = {.data = {0}};
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
