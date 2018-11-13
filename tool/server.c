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
#include "server.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <xtt/crypto_types.h>
#include <xtt/crypto_wrapper.h>
#include <xtt/context.h>
#include <xtt/messages.h>
#include <xtt/util/util_errors.h>
#include <xtt/util/file_io.h>


xtt_version version_g_server = XTT_VERSION_ONE;

xtt_group_id stored_gid = {.data = {0}};
struct xtt_group_public_key_context stored_gpk_ctx;

static int initialize_server(struct xtt_server_certificate_context *cert_ctx,
                struct xtt_server_cookie_context *cookie_ctx,
                const char* daa_gpk_file, const char* basename_file,
                const char* server_privatekey_file, const char* server_certificate_file);

static int open_socket(unsigned short);

static void do_handshake(int client_sock,
                struct xtt_server_certificate_context *cert_ctx,
                struct xtt_server_cookie_context *cookie_ctx);

static struct xtt_group_public_key_context*
lookup_gpk(xtt_group_id *claimed_gid);

static int assign_client_id(xtt_identity_type *assigned_client_id_out,
                                 xtt_identity_type *requested_client_id,
                                 xtt_group_id *gid,
                                 xtt_daa_pseudonym_lrsw *pseudonym);

static void report_results_server(struct xtt_server_handshake_context *ctx);

int run_server(struct cli_params* params)
{
    unsigned short server_port = params->port;
    const char *daa_gpk_file = params->daagpk;
    const char *server_privatekey_file = params->privkey;
    const char* basename_file = params->basename;
    const char* server_certificate_file = params->servercert;

    // 0) Initialize crypto primitives library
    int ret = xtt_crypto_initialize_crypto();
    if (0 != ret) {
        fprintf(stderr, "Error initializing cryptography library: %d\n", ret);
        return SERVER_ERROR;
    }

    // 1) Setup XTT context
    printf("initializing server....\n");
    struct xtt_server_certificate_context cert_ctx;
    struct xtt_server_cookie_context cookie_ctx;
    ret = initialize_server(&cert_ctx, &cookie_ctx, daa_gpk_file, basename_file, server_privatekey_file, server_certificate_file);
    if (0 != ret) {
        fprintf(stderr, "Error initializing server handshake context\n");
        return SERVER_ERROR;
    }
    printf("\tok\n");

    // 2) Listen for incoming connections
    printf("Starting server on port %d ...\n", server_port);
    int my_sock = open_socket(server_port);
    if (my_sock < 0) {
        return SERVER_ERROR;
    }

    // 3) For each incoming connection (sequentially),
    // run the XTT id-provisioning handshake.
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t clientlen = sizeof(client_addr);
        int client_sock = accept(my_sock, (struct sockaddr*)&client_addr, &clientlen);
        if (client_sock < 0) {
            fprintf(stderr, "Error on accept\n");
            continue;
        }
        printf("Got client connection...\n");

        do_handshake(client_sock, &cert_ctx, &cookie_ctx);
    }

    return 0;

}

static
int initialize_server(struct xtt_server_certificate_context *cert_ctx,
               struct xtt_server_cookie_context *cookie_ctx, const char* daa_gpk_file,
                const char* basename_file, const char* server_privatekey_file, const char* server_certificate_file)
{
    int read_ret = 0;
    // 1) Read DAA GPK from file.
    xtt_daa_group_pub_key_lrsw gpk = {.data = {0}};
    read_ret = xtt_read_from_file(daa_gpk_file, gpk.data, sizeof(xtt_daa_group_pub_key_lrsw));
    if (sizeof(xtt_daa_group_pub_key_lrsw) != read_ret) {
        fprintf(stderr, "Error reading DAA GPK from file\n");
        return READ_FROM_FILE_ERROR;
    }

    // 2) Read DAA basename from file
    unsigned char basename[1024] = {0};
    read_ret = xtt_read_from_file(basename_file, basename, sizeof(basename));
    if (read_ret < 0) {
        fprintf(stderr, "Error reading basename from file\n");
        return READ_FROM_FILE_ERROR;
    }

    uint16_t basename_len = (uint16_t)read_ret;

    // 3) Initialize DAA context
    xtt_return_code_type rc = 0;
    rc = xtt_initialize_group_public_key_context_lrsw(&stored_gpk_ctx,
                                                          (unsigned char*)basename,
                                                          basename_len,
                                                          &gpk);
    if (XTT_RETURN_SUCCESS != rc)
        return SERVER_ERROR;

    // 4) Generate GID from GPK (GID = SHA-256(GPK | basename))
    crypto_hash_sha256_state hash_state;
    int hash_ret = crypto_hash_sha256_init(&hash_state);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_update(&hash_state, gpk.data, sizeof(gpk));
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_update(&hash_state, basename, basename_len);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_final(&hash_state, stored_gid.data);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;

    // 5) Read in my certificate from file
    unsigned char serialized_certificate[XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH] = {0};
    read_ret = xtt_read_from_file(server_certificate_file, serialized_certificate, XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH);
    if (XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH != read_ret) {
        fprintf(stderr, "Error reading server certificate from file\n");
        return READ_FROM_FILE_ERROR;
    }

    // 6) Read in my private key from file
    xtt_ecdsap256_priv_key server_private_key = {.data = {0}};
    read_ret = xtt_read_from_file(server_privatekey_file, server_private_key.data, sizeof(xtt_ecdsap256_priv_key));
    if (sizeof(xtt_ecdsap256_priv_key) != read_ret) {
        fprintf(stderr, "Error reading server's private key from file\n");
        return READ_FROM_FILE_ERROR;
    }

    // 7) Initialize my certificate context
    rc = xtt_initialize_server_certificate_context_ecdsap256(cert_ctx,
                                                           serialized_certificate,
                                                           &server_private_key);
    if (XTT_RETURN_SUCCESS != rc)
        return SERVER_ERROR;

    // 8) Initialize my server_cookie context
    rc = xtt_initialize_server_cookie_context(cookie_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return SERVER_ERROR;

    return 0;
}

static
int open_socket(unsigned short server_port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (0 == server_fd) {
        fprintf(stderr, "Error opening server socket\n");
        return SERVER_ERROR;
    }
    int reuse_opt_val = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&reuse_opt_val, sizeof(reuse_opt_val));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error binding to port %d\n", server_port);
        return SERVER_ERROR;
    }

    if (listen(server_fd, 1) < 0) {
        fprintf(stderr, "Error listening on port %d\n", server_port);
        return SERVER_ERROR;
    }

    return server_fd;
}

static void
do_handshake(int client_sock,
             struct xtt_server_certificate_context *cert_ctx,
             struct xtt_server_cookie_context *cookie_ctx)
{
    xtt_return_code_type rc = 0;

    // 1) Initialize handshake context
    unsigned char in_buffer[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH] = {0};
    unsigned char out_buffer[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH] = {0};
    struct xtt_server_handshake_context ctx;
    rc = xtt_initialize_server_handshake_context(&ctx, in_buffer, sizeof(in_buffer), out_buffer, sizeof(out_buffer));
    if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error initializing server handshake context: %d\n", rc);
        return;
    }

    // 2) Start our end of the handshake.
    uint16_t bytes_requested = 0;
    xtt_identity_type requested_client_id = {.data = {0}};
    xtt_group_id claimed_group_id = {.data = {0}};
    unsigned char *io_ptr = NULL;
    rc = xtt_handshake_server_handle_connect(&bytes_requested,
                                             &io_ptr,
                                             &ctx);

    while (XTT_RETURN_HANDSHAKE_FINISHED != rc) {
        switch (rc) {
            case XTT_RETURN_WANT_WRITE:
                {
                    printf("Writing %d bytes...", bytes_requested);
                    int write_ret = write(client_sock, io_ptr, bytes_requested);
                    if (write_ret <= 0) {
                        fprintf(stderr, "Error sending to client\n");
                        close(client_sock);
                        return;
                    }
                    printf("wrote %d bytes\n", write_ret);

                    rc = xtt_handshake_server_handle_io((uint16_t)write_ret,
                                                        0,
                                                        &bytes_requested,
                                                        &io_ptr,
                                                        &ctx);

                    break;
                }
            case XTT_RETURN_WANT_READ:
                {
                    printf("Reading %d bytes...", bytes_requested);
                    int read_ret = read(client_sock, io_ptr, bytes_requested);
                    if (read_ret <= 0) {
                        fprintf(stderr, "Error receiving from client\n");
                        close(client_sock);
                        return;
                    }

                    rc = xtt_handshake_server_handle_io(0,
                                                        (uint16_t)read_ret,
                                                        &bytes_requested,
                                                        &io_ptr,
                                                        &ctx);
                    printf("read %d bytes\n", read_ret);

                    break;
                }
            case XTT_RETURN_WANT_BUILDSERVERATTEST:
                {
                    printf("Received ClientInit. Building ServerAttest...\n");

                    rc = xtt_handshake_server_build_serverattest(&bytes_requested,
                                                                 &io_ptr,
                                                                 &ctx,
                                                                 cert_ctx,
                                                                 cookie_ctx);

                    break;
                }
            case XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST:
                {
                    printf("Received Identity_ClientAttest. Pre-parsing it...\n");

                    rc = xtt_handshake_server_preparse_idclientattest(&bytes_requested,
                                                                      &io_ptr,
                                                                      &requested_client_id,
                                                                      &claimed_group_id,
                                                                      cookie_ctx,
                                                                      cert_ctx,
                                                                      &ctx);

                    break;
                }
            case XTT_RETURN_WANT_VERIFYGROUPSIGNATURE:
                {
                    printf("Looking up GPK from claimed GID...\n");
                    struct xtt_group_public_key_context* gpk_ctx;
                    gpk_ctx = lookup_gpk(&claimed_group_id);
                    if (NULL == gpk_ctx) {
                        (void)xtt_server_build_error_msg(&bytes_requested, &io_ptr, &ctx);
                        int write_ret = write(client_sock, io_ptr, bytes_requested);
                        if (write_ret > 0) {
                            close(client_sock);
                        }
                        return;
                    }

                    printf("Verifying group signature...\n");
                    rc = xtt_handshake_server_verify_groupsignature(&bytes_requested,
                                                                    &io_ptr,
                                                                    gpk_ctx,
                                                                    cert_ctx,
                                                                    &ctx);

                    break;
                }

            case XTT_RETURN_WANT_BUILDIDSERVERFINISHED:
                {
                    printf("Assigning the client an ID...\n");
                    xtt_daa_pseudonym_lrsw clients_pseudonym = {.data = {0}};
                    if (XTT_RETURN_SUCCESS != xtt_get_clients_pseudonym_lrsw(&clients_pseudonym, &ctx)) {
                        printf("Error getting the client's pseudonym!\n");
                        return;
                    }
                    xtt_identity_type assigned_client_id = {.data = {0}};
                    int id_assign_ret = assign_client_id(&assigned_client_id, &requested_client_id, &claimed_group_id, &clients_pseudonym);
                    if (0 != id_assign_ret) {
                        (void)xtt_server_build_error_msg(&bytes_requested, &io_ptr, &ctx);
                        int write_ret = write(client_sock, io_ptr, bytes_requested);
                        if (write_ret > 0) {
                            close(client_sock);
                        }
                        return;
                    }

                    printf("Sending Identity_ServerFinished...\n");
                    rc = xtt_handshake_server_build_idserverfinished(&bytes_requested,
                                                                     &io_ptr,
                                                                     &assigned_client_id,
                                                                     &ctx);

                    break;
                }
            case XTT_RETURN_HANDSHAKE_FINISHED:
                break;
            case XTT_RETURN_RECEIVED_ERROR_MSG:
                fprintf(stderr, "Received error message from client\n");
                close(client_sock);
                return;
            default:
                fprintf(stderr, "Encountered error during server handshake: %d\n", rc);
                (void)xtt_server_build_error_msg(&bytes_requested, &io_ptr, &ctx);
                int write_ret = write(client_sock, io_ptr, bytes_requested);
                if (write_ret > 0) {
                    close(client_sock);
                }
                return;
        }
    }

    close(client_sock);

    if (XTT_RETURN_HANDSHAKE_FINISHED == rc) {
        printf("Handshake completed successfully!\n");

        report_results_server(&ctx);
    }
}

static struct xtt_group_public_key_context*
lookup_gpk(xtt_group_id *claimed_gid)
{
    // 1) See if we can find the claimed GID
    char *found_gpk = NULL;

    if(0 == strncmp((char *)claimed_gid->data, (char *)stored_gid.data, sizeof(xtt_group_id))){
        found_gpk = "found";
    }

    printf("Client claimed gid={");
    for (size_t i=0; i < sizeof(xtt_group_id); ++i) {
        printf("%#02X", claimed_gid->data[i]);
        if (i < (sizeof(xtt_group_id)-1)) {
            printf(", ");
        } else {
            printf("}\n");
        }
    }
    if (NULL != found_gpk) {
        printf("which matches the gid we have!\n");
    } else {
        printf("which does NOT match the gid we have!\nQuitting...\n");
        // close(client_sock);
        return NULL;
    }

    return &stored_gpk_ctx;
}

static int
assign_client_id(xtt_identity_type *assigned_client_id_out,
                 xtt_identity_type *requested_client_id,
                 xtt_group_id *gid,
                 xtt_daa_pseudonym_lrsw *pseudonym)
{
    // 0) In principle, we could use the gid and pseudonym when selecting an id for the client
    // (i.e., use the gid to choose the pool of id's,
    // and use the pseudonym to ensure the same client always gets the same id).
    (void)gid;
    (void)pseudonym;

    // If the client sent xtt_null_client_id assign them a randomly-generated id.
    // Otherwise, just echo back what they requested.
    if (0 == xtt_crypto_memcmp(requested_client_id->data, xtt_null_identity.data, sizeof(xtt_identity_type))) {
        xtt_crypto_get_random(assigned_client_id_out->data, sizeof(xtt_identity_type));
    } else {
        memcpy(assigned_client_id_out->data, requested_client_id->data, sizeof(xtt_identity_type));
    }

    return 0;
}

static void report_results_server(struct xtt_server_handshake_context *ctx)
{
    // 1) Client's ID
    xtt_identity_type assigned_id = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_clients_identity(&assigned_id, ctx)) {
        printf("Error getting the client's assigned client id!\n");
        return;
    }
    printf("We assigned the client the id: {");
    for (size_t i=0; i < sizeof(xtt_identity_type); ++i) {
        printf("%#02X", assigned_id.data[i]);
        if (i < (sizeof(xtt_identity_type)-1)) {
            printf(", ");
        } else {
            printf("}\n");
        }
    }

    // 2) Client's longterm key
    //  Note: we look up the type of the longterm key sent by the client
    //  (via the suite_spec)
    //  but currently we only support Ed25519 signatures for this.
    xtt_suite_spec suite_spec = 0;
    if (XTT_RETURN_SUCCESS != xtt_get_suite_spec(&suite_spec, ctx)) {
        printf("Error getting the suite spec negotiated during the handshake!\n");
        return;
    }
    switch (ctx->base.suite_spec) {
        case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512:
        case XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B:
        case XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512:
        case XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B:
            {
                xtt_ecdsap256_pub_key clients_longterm_key = {.data = {0}};
                if (XTT_RETURN_SUCCESS != xtt_get_clients_longterm_key_ecdsap256(&clients_longterm_key, ctx)) {
                    printf("Error getting the client's longterm key!\n");
                    return;
                }
                printf("The client sent us the longterm key: {");
                for (size_t i=0; i < sizeof(xtt_ecdsap256_pub_key); ++i) {
                    printf("%#02X", clients_longterm_key.data[i]);
                    if (i < (sizeof(xtt_ecdsap256_pub_key)-1)) {
                        printf(", ");
                    } else {
                        printf("}\n");
                    }
                }

                break;
            }
        default:
            printf("Unknown suite_spec used during handshake, which is weird...\n");
            return;
    }

    // 3) Clients DAA pseudonym
    xtt_daa_pseudonym_lrsw clients_pseudonym = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_clients_pseudonym_lrsw(&clients_pseudonym, ctx)) {
        printf("Error getting the client's pseudonym!\n");
        return;
    }
    printf("The client has pseudonym: {");
    for (size_t i=0; i < sizeof(xtt_daa_pseudonym_lrsw); ++i) {
        printf("%#02X", clients_pseudonym.data[i]);
        if (i < (sizeof(xtt_daa_pseudonym_lrsw)-1)) {
            printf(", ");
        } else {
            printf("}\n");
        }
    }

}
