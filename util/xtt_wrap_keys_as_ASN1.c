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

#include <stdio.h>
#include <stdlib.h>

#define SERIALIZED_NAME_LENGTH 32   // 16 ASCII-encoded bytes

struct cli_args {
    char *name_in_filename;
    char *pubkey_in_filename;
    char *privkey_in_filename;
    char *cert_out_filename;
    char *priv_out_filename;
};

int save_to_file(unsigned char *buffer, size_t buffer_length, const char *filename);

int read_from_file(const char *filename, unsigned char *buffer, size_t bytes_to_read);

void parse_cli(int argc, char *argv[], struct cli_args *args);

int main(int argc, char *argv[])
{
    int ret = 0;

    struct cli_args args;
    parse_cli(argc, argv, &args);

    printf("Saving keys from files '%s' and '%s' to certificate '%s', with identity from '%s'...\n",
           args.pubkey_in_filename,
           args.privkey_in_filename,
           args.cert_out_filename,
           args.name_in_filename);

    xtt_identity_type name_buf;
    if (read_from_file(args.name_in_filename, name_buf.data, sizeof(xtt_identity_type))) {
        fprintf(stderr, "Error reading identity in from file '%s'\n", args.name_in_filename);
        ret = 1;
        goto finish;
    }

    xtt_ed25519_pub_key pubkey_buf;
    if (read_from_file(args.pubkey_in_filename, pubkey_buf.data, sizeof(xtt_ed25519_pub_key))) {
        fprintf(stderr, "Error reading public key in from file '%s'\n", args.pubkey_in_filename);
        ret = 1;
        goto finish;
    }

    xtt_ed25519_priv_key privkey_buf;
    if (read_from_file(args.privkey_in_filename, privkey_buf.data, sizeof(xtt_ed25519_priv_key))) {
        fprintf(stderr, "Error reading private key in from file '%s'\n", args.privkey_in_filename);
        ret = 1;
        goto finish;
    }

    unsigned char cert_buf[XTT_X509_CERTIFICATE_LENGTH];
    if (0 != xtt_x509_from_ed25519_keypair(&pubkey_buf, &privkey_buf, &name_buf, cert_buf, sizeof(cert_buf))) {
        fprintf(stderr, "Error creating X509 certificate\n");
        ret = 1;
        goto finish;
    }

    if (0 != save_to_file(cert_buf, sizeof(cert_buf), args.cert_out_filename)) {
        fprintf(stderr, "Error saving X509 certificate to file\n");
        ret = 1;
        goto finish;
    }

    unsigned char asn1_priv_buf[XTT_ASN1_PRIVATE_KEY_LENGTH];
    if (0 != xtt_asn1_from_ed25519_private_key(&privkey_buf, asn1_priv_buf, sizeof(asn1_priv_buf))) {
        fprintf(stderr, "Error creating ASN.1 private key\n");
        ret = 1;
        goto finish;
    }

    if (0 != save_to_file(asn1_priv_buf, sizeof(asn1_priv_buf), args.priv_out_filename)) {
        fprintf(stderr, "Error saving ASN.1 private key to file\n");
        ret = 1;
        goto finish;
    }

    printf("\tok\n");
finish:
    return ret;
}


void parse_cli(int argc, char *argv[], struct cli_args *args)
{
    const char *usage = "usage: %s <identity-file> <public-key-in-file> <private-key-in-file> [certificate-out-file] [private-key-out-file]\n"
                        "\tidentity-file            - File with XTT identity\n"
                        "\tpublic-key-in-file       - File with raw Ed25519 public key\n"
                        "\tprivate-key-in-file      - File with raw Ed25519 private key\n"
                        "\tcertificate-out-file     - Location to save X509 self-signed certificate         (default: 'cert.bin')\n"
                        "\tprivate-key-out-file     - Location to save ASN.1-encoded Ed25519 private key    (default: 'priv_asn1.bin')\n"
                        "\t\tIf either cert-out-file or private-key-out-file is given, BOTH must be given\n";

    if (6 == argc) {
        args->name_in_filename = argv[1];
        args->pubkey_in_filename = argv[2];
        args->privkey_in_filename = argv[3];
        args->cert_out_filename = argv[4];
        args->priv_out_filename = argv[5];
    } else if (4 == argc) {
        args->name_in_filename = argv[1];
        args->pubkey_in_filename = argv[2];
        args->privkey_in_filename = argv[3];
        args->cert_out_filename = "cert.bin";
        args->priv_out_filename = "priv_asn1.bin";
    } else {
        fprintf(stderr, "Incorrect number of arguments given\n");
        fprintf(stderr, usage, argv[0]);

        exit(1);
    }
}

int save_to_file(unsigned char *buffer, size_t buffer_length, const char *filename)
{
    FILE *file_ptr = fopen(filename, "wb");

    if (NULL == file_ptr)
        return -1;

    int ret = 0;

    size_t bytes_written = fwrite(buffer, 1, buffer_length, file_ptr);

    if (buffer_length != bytes_written) {
        fprintf(stderr, "Error writing to file '%s'\n", filename);
        ret = -1;
        goto cleanup;
    }

cleanup:
    (void)fclose(file_ptr);

    return ret;
}

int read_from_file(const char *filename, unsigned char *buffer, size_t bytes_to_read)
{
    FILE *file_ptr = fopen(filename, "rb");

    if (NULL == file_ptr)
        return -1;

    int ret = 0;

    size_t bytes_read = fread(buffer, 1, bytes_to_read, file_ptr);

    if (bytes_to_read != bytes_read) {
        fprintf(stderr, "Error reading file '%s'\n", filename);
        ret = -1;
        goto cleanup;
    }

cleanup:
    (void)fclose(file_ptr);

    return ret;
}

