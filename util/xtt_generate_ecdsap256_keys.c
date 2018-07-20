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

#include <stdio.h>
#include <stdlib.h>

struct cli_args {
    char *pubkey_out_filename;
    char *privkey_out_filename;
};

int save_to_file(unsigned char *buffer, size_t buffer_length, const char *filename);

void parse_cli(int argc, char *argv[], struct cli_args *args);

int main(int argc, char *argv[])
{
    int ret = 0;

    struct cli_args args;
    parse_cli(argc, argv, &args);

    printf("Generating ecdsap256 keys to files '%s' and '%s'...\n", args.pubkey_out_filename, args.privkey_out_filename);
    xtt_ecdsap256_pub_key pub;
    xtt_ecdsap256_priv_key priv;
    if (0 != xtt_crypto_create_ecdsap256_key_pair(&pub, &priv)) {
        fprintf(stderr, "Error creating ecdsap256 keypair\n");
        ret = 1;
        goto finish;
    }

    if (0 != save_to_file(pub.data, sizeof(xtt_ecdsap256_pub_key), args.pubkey_out_filename)) {
        ret = 1;
        goto finish;
    }

    if (0 != save_to_file(priv.data, sizeof(xtt_ecdsap256_priv_key), args.privkey_out_filename)) {
        ret = 1;
        goto finish;
    }

    printf("\tok\n");
finish:
    return ret;
}

void parse_cli(int argc, char *argv[], struct cli_args *args)
{
    const char *usage = "usage: %s [public-key-out-file=pub.bin] [private-key-out-file=priv.bin]\n"
                        "\tIf either public-key-out-file or private-key-out-file is given, BOTH must be given\n";

    if (3 == argc) {
        args->pubkey_out_filename = argv[1];
        args->privkey_out_filename = argv[2];
    } else if (1 == argc) {
        args->pubkey_out_filename = "pub.bin";
        args->privkey_out_filename = "priv.bin";
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
