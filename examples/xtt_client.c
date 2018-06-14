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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>

#define MAX_SERVER_IP_LENGTH 16
#define MAX_TPM_DEV_FILE_LENGTH 128

#ifdef USE_TPM
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_socket.h>
#include <tss2/tss2_tcti_device.h>
unsigned char tcti_context_buffer_g[256];
#endif

uint32_t key_handle_g = 0x81800000;
uint32_t gpk_handle_g = 0x1410000;
uint32_t cred_handle_g = 0x1410001;
uint32_t root_id_handle_g = 0x1410003;
uint32_t root_pubkey_handle_g = 0x1410004;
uint32_t basename_size_handle_g = 0x1410006;
uint32_t basename_handle_g = 0x1410007;
uint32_t server_id_handle_g = 0x1410008;
const char *tpm_hostname_g = "localhost";
const char *tpm_port_g = "2321";
const size_t tpm_devfile_length_g = 9;
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
const char *assigned_client_id_out_file = "assigned_identity.txt";
const char *longterm_public_key_out_file = "longterm_certificate.asn1.bin";
const char *longterm_private_key_out_file = "longterm_priv.asn1.bin";

// We have a toy "database" of server certificates
typedef struct {
    xtt_certificate_root_id root_id;
    struct xtt_server_root_certificate_context cert;
} certificate_db_record;
certificate_db_record certificate_db[1];
const size_t certificate_db_size = 1;

typedef enum {
    XTT_TCTI_SOCKET,
    XTT_TCTI_DEVICE,
} xtt_tcti_type;

void parse_cmd_args(int argc, char *argv[], xtt_suite_spec *suite_spec, char *ip,
        unsigned short *port, int *use_tpm, xtt_tcti_type *tcti_type, char *dev_file,
        xtt_identity_type *requested_client_id);

int connect_to_server(const char *ip, unsigned short port);

int initialize_server_id(xtt_identity_type *intended_server_id,
                         int use_tpm,
                         xtt_tcti_type tcti_type,
                         const char* dev_file);

int initialize_certs(int use_tpm);

int initialize_daa(struct xtt_client_group_context *group_ctx, int use_tpm, xtt_tcti_type tcti_type, const char* dev_file);

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
    int ret = 0;

    int init_ret = xtt_crypto_initialize_crypto();
    if (0 != init_ret) {
        fprintf(stderr, "Error initializing cryptography library: %d\n", init_ret);
        return 1;
    }

    int init_daa_ret = -1;
    int socket = -1;

    // 0) Parse the command line args
    xtt_suite_spec suite_spec;
    char server_ip[MAX_SERVER_IP_LENGTH];
    unsigned short server_port;
    int use_tpm;
    xtt_tcti_type tcti_type;
    char tcti_dev_file[MAX_TPM_DEV_FILE_LENGTH];
    xtt_identity_type requested_client_id;
    parse_cmd_args(argc, argv, &suite_spec, server_ip, &server_port, &use_tpm, &tcti_type, tcti_dev_file, &requested_client_id);

    // 1) Setup the needed XTT contexts (from files).
    struct xtt_client_group_context group_ctx;
    init_daa_ret = initialize_daa(&group_ctx, use_tpm, tcti_type, tcti_dev_file);
    ret = init_daa_ret;
    if (0 != init_daa_ret) {
        fprintf(stderr, "Error initializing DAA context\n");
        goto finish;
    }
    ret = initialize_certs(use_tpm);
    if (0 != ret) {
        fprintf(stderr, "Error initializing server/root certificate contexts\n");
        goto finish;
    }

    // 2) Set the intended server id.
    xtt_identity_type intended_server_id;
    ret = initialize_server_id(&intended_server_id, use_tpm, tcti_type, tcti_dev_file);
    if(0 != ret) {
        fprintf(stderr, "Error setting XTT server ID!\n");
        goto finish;
    }

    // 3) Make TCP connection to server.
    printf("Connecting to server at %s:%d ...\t", server_ip, server_port);
    socket = connect_to_server(server_ip, server_port);
    if (socket < 0) {
        ret = 1;
        goto finish;
    }
    printf("ok\n");

    // 4) Initialize XTT handshake context
    // (will be populated with useful information after a successful handshake).
    printf("Using suite_spec = %d\n", suite_spec);
    unsigned char in_buffer[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
    unsigned char out_buffer[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
    struct xtt_client_handshake_context ctx;
    xtt_return_code_type rc = xtt_initialize_client_handshake_context(&ctx, in_buffer, sizeof(in_buffer), out_buffer, sizeof(out_buffer), version_g, suite_spec);
    if (XTT_RETURN_SUCCESS != rc) {
        ret = 1;
        fprintf(stderr, "Error initializing client handshake context: %d\n", rc);
        goto finish;
    }

    // 5) Run the identity-provisioning handshake with the server.
    ret = do_handshake(socket,
                       &requested_client_id,
                       &intended_server_id,
                       &group_ctx,
                       &ctx);
    if (0 == ret) {
        // 6) Print the results (what we and the server now agree on post-handshake)
        ret = report_results(&requested_client_id,
                             &ctx);
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
    if (use_tpm && 0==init_daa_ret) {
        TSS2_TCTI_CONTEXT *tcti_context = (TSS2_TCTI_CONTEXT*)tcti_context_buffer_g;
        tss2_tcti_finalize(tcti_context);
    }
#endif
    if (0 == ret) {
        return 0;
    } else {
        return 1;
    }
}

void parse_cmd_args(int argc, char *argv[], xtt_suite_spec *suite_spec,
        char *ip, unsigned short *port, int *use_tpm, xtt_tcti_type *tcti_type, char *dev_file,
        xtt_identity_type *requested_client_id)
{

    // Set defaults
    *suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512;
    strcpy(ip, "127.0.0.1");
    *port = 4444;
    *use_tpm = 0;
    *tcti_type = XTT_TCTI_DEVICE;
    strcpy(dev_file, "/dev/tpm0");
    *requested_client_id = xtt_null_identity;

    // Parse args
    int c;
    while ((c = getopt(argc, argv, "ms:a:p:t:d:i:h")) != -1) {
        switch (c) {
            case 'm':
                *use_tpm = 1;
                break;
            case 's':
                if (0 == strcmp(optarg, "X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512")) {
                    *suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512;
                } else if (0 == strcmp(optarg, "X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B")) {
                    *suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B;
                } else if (0 == strcmp(optarg, "X25519_LRSW_ED25519_AES256GCM_SHA512")) {
                    *suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_SHA512;
                } else if (0 == strcmp(optarg, "X25519_LRSW_ED25519_AES256GCM_BLAKE2B")) {
                    *suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B;
                } else {
                    fprintf(stderr, "Unknown suite_spec '%s'\n", optarg);
                    exit(1);
                }
                break;
            case 'a':
            {
                size_t ip_opt_len = strlen(optarg);
                if (ip_opt_len > MAX_SERVER_IP_LENGTH) {
                    fprintf(stderr, "Provided server IP address is too long (> %d)\n", MAX_SERVER_IP_LENGTH);
                    exit(1);
                }
                strncpy(ip, optarg, MAX_SERVER_IP_LENGTH-1);
                break;
            }
            case 'p':
                *port = atoi(optarg);
                break;
            case 't':
                if (0 == strcmp(optarg, "device")) {
                    *tcti_type = XTT_TCTI_DEVICE;
                } else if (0 == strcmp(optarg, "socket")) {
                    *tcti_type = XTT_TCTI_SOCKET;
                } else {
                    fprintf(stderr, "Unknown tcti_type '%s'\n", optarg);
                    exit(1);
                }
                break;
            case 'd':
            {
                size_t dev_opt_len = strlen(optarg);
                if (dev_opt_len > MAX_TPM_DEV_FILE_LENGTH) {
                    fprintf(stderr, "Provided TPM TCTI device file is too long (> %d)\n", MAX_TPM_DEV_FILE_LENGTH);
                    exit(1);
                }
                strncpy(dev_file, optarg, MAX_TPM_DEV_FILE_LENGTH-1);
                break;
            }
            case 'i':
            {
                size_t serverid_opt_len = strlen(optarg);
                if (serverid_opt_len != 2*sizeof(xtt_identity_type)) {
                    fprintf(stderr, "Provided requested client ID is the wrong length (must be 32 characters)");
                    exit(1);
                }
                char *end;
                char digit_str[3];
                digit_str[2] = 0;
                for (unsigned i=0; i<sizeof(xtt_identity_type); ++i) {
                    memcpy(digit_str, &optarg[2*i], 2);
                    requested_client_id->data[i] = strtoul(digit_str, &end, 16);
                }
                break;
            }
            case 'h':
                fprintf(stderr, "usage: %s [-m] [-i <requested_client_id>] [-s <suite_spec>] [-a <server_ip>] [-p <server_port>] [-t <tcti_type>] [-d <tcti_device_file>]\n", argv[0]);
                fprintf(stderr, "\tsuite_spec can be one of the following:\n");
                fprintf(stderr, "\t\tX25519_LRSW_ED25519_CHACHA20POLY1305_SHA512 (default)\n");
                fprintf(stderr, "\t\tX25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B\n");
                fprintf(stderr, "\t\tX25519_LRSW_ED25519_AES256GCM_SHA512\n");
                fprintf(stderr, "\t\tX25519_LRSW_ED25519_AES256GCM_BLAKE2B\n");
                fprintf(stderr, "\trequested_client_id is the 32-byte ASCII-encoded client ID to request from the server\n");
                fprintf(stderr, "\t\txtt_client_id_null (default)\n");
                fprintf(stderr, "\tserver_ip is the dotted-decimal address of the XTT server to connect to\n");
                fprintf(stderr, "\t\t127.0.0.1 (default)\n");
                fprintf(stderr, "\tserver_port is the TCP port of the XTT server to connect to\n");
                fprintf(stderr, "\t\t4444 (default)\n");
                fprintf(stderr, "\t-m indicates to use a TPM, not local files\n");
                fprintf(stderr, "\tThe following options are ignored unless -m is specified:\n");
                fprintf(stderr, "\t\ttcti_type can be one of the following:\n");
                fprintf(stderr, "\t\t\tdevice (default)\n");
                fprintf(stderr, "\t\t\tsocket\n");
                fprintf(stderr, "\t\ttcti_device_file is ignored unless tcti_type==device\n");
                fprintf(stderr, "\t\t\t/dev/tpm0 (default)\n");
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

int initialize_server_id(xtt_identity_type *intended_server_id,
                         int use_tpm,
                         xtt_tcti_type tcti_type,
                         const char* dev_file)
{
    int read_ret;

    // Set server's id from file/NVRAM
    if (use_tpm) {
#ifdef USE_TPM
        TSS2_TCTI_CONTEXT *tcti_context = (TSS2_TCTI_CONTEXT*)tcti_context_buffer_g;
        switch (tcti_type) {
            case XTT_TCTI_SOCKET:
                assert(tss2_tcti_getsize_socket() < sizeof(tcti_context_buffer_g));
                if (TSS2_RC_SUCCESS != tss2_tcti_init_socket(tpm_hostname_g, tpm_port_g, tcti_context)) {
                    fprintf(stderr, "Error: Unable to initialize socket TCTI context\n");
                    return -1;
                }
                break;
            case XTT_TCTI_DEVICE:
                assert(tss2_tcti_getsize_device() < sizeof(tcti_context_buffer_g));
                if (TSS2_RC_SUCCESS != tss2_tcti_init_device(dev_file, strlen(dev_file), tcti_context)) {
                    fprintf(stderr, "Error: Unable to initialize device TCTI context\n");
                    return -1;
                }
                break;
        }

        int nvram_ret;
        nvram_ret = read_nvram(intended_server_id->data,
                               sizeof(xtt_identity_type),
                               server_id_handle_g,
                               tcti_context);
        if (0 != nvram_ret) {
            fprintf(stderr, "Error reading server id from TPM NVRAM");
            return -1;
        }
#else
        fprintf(stderr, "Attempted to use a TPM, but not built with TPM enabled!\n");
        return -1;
#endif
    } else {
        read_ret = read_file_into_buffer(intended_server_id->data, sizeof(xtt_identity_type), server_id_file);
        if (sizeof(xtt_identity_type) != read_ret) {
            fprintf(stderr, "Error reading server's ID from file\n");
            return -1;
        }
    }

    return 0;
}

int initialize_daa(struct xtt_client_group_context *group_ctx, int use_tpm, xtt_tcti_type tcti_type, const char* dev_file)
{
    (void)write_buffer_to_file;
    xtt_return_code_type rc;
    int read_ret;

#ifdef USE_TPM
    TSS2_TCTI_CONTEXT *tcti_context;
    if (use_tpm) {
        tcti_context = (TSS2_TCTI_CONTEXT*)tcti_context_buffer_g;
        switch (tcti_type) {
            case XTT_TCTI_SOCKET:
                assert(tss2_tcti_getsize_socket() < sizeof(tcti_context_buffer_g));
                if (TSS2_RC_SUCCESS != tss2_tcti_init_socket(tpm_hostname_g, tpm_port_g, tcti_context)) {
                    fprintf(stderr, "Error: Unable to initialize socket TCTI context\n");
                    return -1;
                }
                break;
            case XTT_TCTI_DEVICE:
                assert(tss2_tcti_getsize_device() < sizeof(tcti_context_buffer_g));
                if (TSS2_RC_SUCCESS != tss2_tcti_init_device(dev_file, strlen(dev_file), tcti_context)) {
                    fprintf(stderr, "Error: Unable to initialize device TCTI context\n");
                    return -1;
                }
        }
    }
#endif

    // 1) Read DAA-related things in from file/TPM-NVRAM
    xtt_daa_group_pub_key_lrsw gpk;
    xtt_daa_credential_lrsw cred;
    xtt_daa_priv_key_lrsw daa_priv_key;
    unsigned char basename[1024];
    uint16_t basename_len = 0;
    if (use_tpm) {
#ifdef USE_TPM
        int nvram_ret;
        uint8_t basename_len_from_tpm = 0;
        nvram_ret = read_nvram((unsigned char*)&basename_len_from_tpm,
                               1,
                               basename_size_handle_g,
                               tcti_context);
        if (0 != nvram_ret) {
            fprintf(stderr, "Error reading basename size from TPM NVRAM\n");
            return -1;
        }
        basename_len = basename_len_from_tpm;
        nvram_ret = read_nvram(basename,
                               basename_len,
                               basename_handle_g,
                               tcti_context);
        if (0 != nvram_ret) {
            fprintf(stderr, "Error reading basename from TPM NVRAM\n");
            return -1;
        }

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
        read_ret = read_file_into_buffer(basename, sizeof(basename), basename_file);
        if (read_ret < 0) {
            fprintf(stderr, "Error reading basename from file\n");
            return -1;
        }
        basename_len = (uint16_t)read_ret;
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
    int write_ret;

    // Get assigned ID
    xtt_identity_type my_assigned_id;
    if (XTT_RETURN_SUCCESS != xtt_get_my_identity(&my_assigned_id, ctx)) {
        printf("Error getting my assigned client id!\n");
        return 1;
    }
    xtt_identity_string my_assigned_id_as_string;
    int convert_ret = xtt_identity_to_string(&my_assigned_id, &my_assigned_id_as_string);
    if (0 != convert_ret) {
        fprintf(stderr, "Error converting assigned id to string\n");
        return 1;
    }
    printf("Server assigned me id: %s\n", my_assigned_id_as_string.data);
    write_ret = write_buffer_to_file(assigned_client_id_out_file, (unsigned char*)my_assigned_id_as_string.data, sizeof(xtt_identity_string));
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

    // Get longterm keypair
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
    xtt_ed25519_priv_key my_longterm_private_key;
    if (XTT_RETURN_SUCCESS != xtt_get_my_longterm_private_key_ed25519(&my_longterm_private_key, ctx)) {
        printf("Error getting my longterm private key!\n");
        return 1;
    }

    // Save longterm keypair as X509 certificate and ASN.1-encoded private key
    unsigned char cert_buf[XTT_X509_CERTIFICATE_LENGTH];
    if (0 != xtt_x509_from_ed25519_keypair(&my_longterm_key, &my_longterm_private_key, &my_assigned_id, cert_buf, sizeof(cert_buf))) {
        fprintf(stderr, "Error creating X509 certificate\n");
        return 1;
    }
    write_ret = write_buffer_to_file(longterm_public_key_out_file, cert_buf, sizeof(cert_buf));
    if (sizeof(cert_buf) != write_ret) {
        fprintf(stderr, "Error writing longterm public key certificate to file\n");
        return 1;
    }
    unsigned char asn1_priv_buf[XTT_ASN1_PRIVATE_KEY_LENGTH];
    if (0 != xtt_asn1_from_ed25519_private_key(&my_longterm_private_key, asn1_priv_buf, sizeof(asn1_priv_buf))) {
        fprintf(stderr, "Error creating ASN.1 private key\n");
        return 1;
    }
    write_ret = write_buffer_to_file(longterm_private_key_out_file, asn1_priv_buf, sizeof(asn1_priv_buf));
    if (sizeof(asn1_priv_buf) != write_ret) {
        fprintf(stderr, "Error writing longterm private key to ASN.1 file\n");
        return 1;
    }

    // Get pseudonym
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
