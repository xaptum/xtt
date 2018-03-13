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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

xtt_version version_g = XTT_VERSION_ONE;

const char *daa_gpk_file = "daa_gpk.bin";
const char *basename_file = "basename.bin";
const char *server_certificate_file = "server_certificate.bin";
const char *server_privatekey_file = "server_privatekey.bin";
const char *root_id_file = "root_id.bin";
const char *root_pubkey_file = "root_pub.bin";

// We have a toy "database" of client group public keys
typedef struct {
    xtt_group_id gid;
    struct xtt_group_public_key_context gpk_ctx;
} gpk_db_record;
gpk_db_record gpk_db[1];
const size_t gpk_db_size = 1;

void parse_cmd_args(int argc, char *argv[], unsigned short *port);

int initialize(struct xtt_server_root_certificate_context *root_certificate,
               struct xtt_server_certificate_context *cert_ctx,
               struct xtt_server_cookie_context *cookie_ctx);

int open_socket(unsigned short);

void do_handshake(int client_sock,
                  struct xtt_server_certificate_context *cert_ctx,
                  struct xtt_server_cookie_context *cookie_ctx);

struct xtt_group_public_key_context*
lookup_gpk(xtt_group_id *claimed_gid);

int
assign_client_id(xtt_identity_type *assigned_client_id_out,
                 xtt_identity_type *requested_client_id,
                 xtt_group_id *gid,
                 xtt_daa_pseudonym_lrsw *pseudonym);

void report_results(struct xtt_server_handshake_context *ctx);

int main(int argc, char *argv[])
{
    // 0) Parse the command line args
    unsigned short server_port;
    parse_cmd_args(argc, argv, &server_port);

    // 1) Setup XTT context
    struct xtt_server_root_certificate_context root_certificate;
    struct xtt_server_certificate_context cert_ctx;
    struct xtt_server_cookie_context cookie_ctx;
    if (0 != initialize(&root_certificate, &cert_ctx, &cookie_ctx)) {
        fprintf(stderr, "Error initializing server handshake context\n");
        return 1;
    }

    // 2) Listen for incoming connections
    printf("Starting server on port %d ...\n", server_port);
    int my_sock = open_socket(server_port);
    if (my_sock < 0) {
        return 1;
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

void parse_cmd_args(int argc, char *argv[], unsigned short *port)
{
    if (2 != argc) {
        fprintf(stderr, "usage: %s <server port>\n", argv[0]);
        exit(1);
    }

    *port = atoi(argv[1]);
}

int initialize(struct xtt_server_root_certificate_context *root_certificate,
               struct xtt_server_certificate_context *cert_ctx,
               struct xtt_server_cookie_context *cookie_ctx)
{
    int read_ret;
    (void)write_buffer_to_file;

    // 1) Read DAA GPK from file.
    xtt_daa_group_pub_key_lrsw gpk;
    read_ret = read_file_into_buffer(gpk.data, sizeof(xtt_daa_group_pub_key_lrsw), daa_gpk_file);
    if (sizeof(xtt_daa_group_pub_key_lrsw) != read_ret) {
        fprintf(stderr, "Error reading DAA GPK from file\n");
        return 1;
    }
    
    // 2) Read DAA basename from file
    unsigned char basename[1024];
    read_ret = read_file_into_buffer(basename, sizeof(basename), basename_file);
    if (read_ret < 0) {
        fprintf(stderr, "Error reading basename from file\n");
        return 1;
    }
    uint16_t basename_len = (uint16_t)read_ret;

    // 3) Initialize DAA context
    xtt_return_code_type rc;
    rc = xtt_initialize_group_public_key_context_lrsw(&gpk_db[0].gpk_ctx,
                                                          (unsigned char*)basename,
                                                          basename_len,
                                                          &gpk);
    if (XTT_RETURN_SUCCESS != rc)
        return -1;

    // 4) Generate GID from GPK (GID = SHA-256(GPK))
    int hash_ret = crypto_hash_sha256(gpk_db[0].gid.data, gpk.data, sizeof(gpk));
    if (0 != hash_ret)
        return -1;

    // 5) Read in my certificate from file
    unsigned char serialized_certificate[XTT_SERVER_CERTIFICATE_ED25519_LENGTH];
    read_ret = read_file_into_buffer(serialized_certificate, XTT_SERVER_CERTIFICATE_ED25519_LENGTH, server_certificate_file);
    if (XTT_SERVER_CERTIFICATE_ED25519_LENGTH != read_ret) {
        fprintf(stderr, "Error reading server certificate from file\n");
        return -1;
    }

    // 6) Read in my private key from file
    xtt_ed25519_priv_key server_private_key;
    read_ret = read_file_into_buffer(server_private_key.data, sizeof(xtt_ed25519_priv_key), server_privatekey_file);
    if (sizeof(xtt_ed25519_priv_key) != read_ret) {
        fprintf(stderr, "Error reading server's private key from file\n");
        return -1;
    }

    // 7) Initialize my certificate context
    rc = xtt_initialize_server_certificate_context_ed25519(cert_ctx,
                                                           serialized_certificate,
                                                           &server_private_key);
    if (XTT_RETURN_SUCCESS != rc)
        return -1;

    // 8) Read in the root id from file
    xtt_certificate_root_id root_id;
    read_ret = read_file_into_buffer(root_id.data, sizeof(xtt_certificate_root_id), root_id_file);
    if (sizeof(xtt_certificate_root_id) != read_ret) {
        fprintf(stderr, "Error reading root's id from file\n");
        return 1;
    }

    // 9) Read in the root public key from file
    xtt_ed25519_pub_key root_public_key;
    read_ret = read_file_into_buffer(root_public_key.data, sizeof(xtt_ed25519_pub_key), root_pubkey_file);
    if (sizeof(xtt_ed25519_pub_key) != read_ret) {
        fprintf(stderr, "Error reading root's public key from file\n");
        return 1;
    }

    // 10) Initialize root certificate context
    rc = xtt_initialize_server_root_certificate_context_ed25519(root_certificate,
                                                                &root_id,
                                                                &root_public_key);
    if (XTT_RETURN_SUCCESS != rc)
        return -1;

    // 11) Initialize my server_cookie context
    rc = xtt_initialize_server_cookie_context(cookie_ctx);
    if (XTT_RETURN_SUCCESS != rc)
        return -1;

    return 0;
}

int open_socket(unsigned short server_port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (0 == server_fd) {
        fprintf(stderr, "Error opening server socket\n");
        return -1;
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
        return -1;
    }

    if (listen(server_fd, 1) < 0) {
        fprintf(stderr, "Error listening on port %d\n", server_port);
        return -1;
    }

    return server_fd;
}

void
do_handshake(int client_sock,
             struct xtt_server_certificate_context *cert_ctx,
             struct xtt_server_cookie_context *cookie_ctx)
{
    xtt_return_code_type rc;

    // 1) Initialize handshake context
    unsigned char in_buffer[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
    unsigned char out_buffer[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
    struct xtt_server_handshake_context ctx;
    rc = xtt_initialize_server_handshake_context(&ctx, in_buffer, sizeof(in_buffer), out_buffer, sizeof(out_buffer));
    if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error initializing server handshake context: %d\n", rc);
        return;
    }

    // 2) Start our end of the handshake.
    uint16_t bytes_requested = 0;
    xtt_identity_type requested_client_id;
    xtt_group_id claimed_group_id;
    unsigned char *io_ptr = NULL;
    rc = xtt_handshake_server_handle_clientinit(&bytes_requested,
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
            case XTT_RETURN_WANT_BUILDIDSERVERFINISHED:
                {
                    printf("Looking up GPK from claimed GID...\n");
                    struct xtt_group_public_key_context* gpk_ctx;
                    gpk_ctx = lookup_gpk(&claimed_group_id);
                    if (NULL == gpk_ctx) {
                        unsigned char err_buffer[16];
                        (void)build_error_msg(err_buffer, &bytes_requested, version_g);
                        int write_ret = write(client_sock, err_buffer, bytes_requested);
                        if (write_ret > 0) {
                            close(client_sock);
                        }
                        return;
                    }

                    printf("Assigning the client an ID...\n");
                    xtt_daa_pseudonym_lrsw clients_pseudonym;
                    if (XTT_RETURN_SUCCESS != xtt_get_clients_pseudonym_lrsw(&clients_pseudonym, &ctx)) {
                        printf("Error getting the client's pseudonym!\n");
                        return;
                    }
                    xtt_identity_type assigned_client_id;
                    int id_assign_ret = assign_client_id(&assigned_client_id, &requested_client_id, &claimed_group_id, &clients_pseudonym);
                    if (0 != id_assign_ret) {
                        unsigned char err_buffer[16];
                        (void)build_error_msg(err_buffer, &bytes_requested, version_g);
                        int write_ret = write(client_sock, err_buffer, bytes_requested);
                        if (write_ret > 0) {
                            close(client_sock);
                        }
                        return;
                    }

                    printf("Sending Identity_ServerFinished...\n");
                    rc = xtt_handshake_server_build_idserverfinished(&bytes_requested,
                                                                     &io_ptr,
                                                                     &assigned_client_id,
                                                                     gpk_ctx,
                                                                     cert_ctx,
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
                // Send error message
                (void)write(client_sock, io_ptr, bytes_requested);
                close(client_sock);
                return;
        }
    }

    if (XTT_RETURN_HANDSHAKE_FINISHED == rc) {
        printf("Handshake completed successfully!\n");

        report_results(&ctx);
    }
}

struct xtt_group_public_key_context*
lookup_gpk(xtt_group_id *claimed_gid)
{
    // 1) See if we can find the claimed GID
    gpk_db_record *found_gpk = NULL;
    for (size_t i=0; i < gpk_db_size; ++i) {
        int cmp_ret = xtt_crypto_memcmp(gpk_db[i].gid.data,
                                        claimed_gid->data,
                                        sizeof(xtt_group_id));
        if (0 == cmp_ret) {
            found_gpk = &gpk_db[i];
            break;
        }
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

    return &found_gpk->gpk_ctx;
}

int
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
        if (0 != xtt_crypto_get_random(assigned_client_id_out->data, sizeof(xtt_identity_type))) {
            fprintf(stderr, "Client requested an id assignment, but there was an error generating it!\n");
            return -1;
            // close(client_sock);
            // goto finished_handshake;
        }
    } else {
        memcpy(assigned_client_id_out->data, requested_client_id->data, sizeof(xtt_identity_type));
    }

    return 0;
}

void report_results(struct xtt_server_handshake_context *ctx)
{
    // 1) Client's ID
    xtt_identity_type assigned_id;
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
    //  (via the suite_spec),
    //  but currently we only support Ed25519 signatures for this.
    xtt_suite_spec suite_spec;
    if (XTT_RETURN_SUCCESS != xtt_get_suite_spec(&suite_spec, ctx)) {
        printf("Error getting the suite spec negotiated during the handshake!\n");
        return;
    }
    switch (ctx->base.suite_spec) {
        case XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512:
        case XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B:
        case XTT_X25519_LRSW_ED25519_AES256GCM_SHA512:
        case XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B:
            {
                xtt_ed25519_pub_key clients_longterm_key;
                if (XTT_RETURN_SUCCESS != xtt_get_clients_longterm_key_ed25519(&clients_longterm_key, ctx)) {
                    printf("Error getting the client's longterm key!\n");
                    return;
                }
                printf("The client sent us the longterm key: {");
                for (size_t i=0; i < sizeof(xtt_ed25519_pub_key); ++i) {
                    printf("%#02X", clients_longterm_key.data[i]);
                    if (i < (sizeof(xtt_ed25519_pub_key)-1)) {
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
    xtt_daa_pseudonym_lrsw clients_pseudonym;
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
