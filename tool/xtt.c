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
#include "client.h"
#include "parse_cli.h"
#include "infocert.h"
#include "generate_ecdsap256_keypair.h"
#ifdef USE_TPM
#include "read_nvram.h"
#endif

#include <xtt/crypto_wrapper.h>
#include <xtt/util/generate_x509_certificate.h>
#include <xtt/util/root.h>
#include <xtt/util/generate_server_certificate.h>
#include <xtt/util/util_errors.h>

#include <stdio.h>

int main(int argc, char **argv)
{
    // Initialize crypto primitives library
    int ret = xtt_crypto_initialize_crypto();
    if (0 != ret) {
        fprintf(stderr, "Error initializing cryptography library: %d\n", ret);
        return 1;
    }


    struct cli_params params;
    parse_cli(argc, argv, &params);
    int out = 0;
    switch(params.command) {
        case action_genkey:
            out = xtt_generate_ecdsap256_keypair(params.keypair);
            break;
        case action_genx509cert:
            out = xtt_generate_x509_certificate(params.keypair, params.id, params.cert);
            break;
        case action_genrootcert:
            out = xtt_generate_root(params.keypair, params.id, params.rootcert);
            break;
        case action_genservercert:
            out = xtt_generate_server_certificate(params.rootcert, params.keypair, params.certreserved, params.serverkeypair, params.servercert);
            break;
        case action_runserver:
            out = run_server(&params);
            break;
        case action_runclient:
            out = run_client(&params);
            break;
        case action_infocert: {
            enum infocert_type type;
            if (params.servercert != NULL) {
                type = infocert_type_server;
                out = info_cert(params.servercert, type);
            } else if (params.rootcert != NULL) {
                type = infocert_type_root;
                out = info_cert(params.rootcert, type);
            } else {
                out = ASN1_PARSE_ERROR;
            }
            break;
        }
        case action_readnvram: {
#ifdef USE_TPM
            out = read_nvram(&params.tpm_params, params.outfile, params.obj_name);
#else
            fprintf(stderr, "Attempted to use a TPM, but not built with TPM enabled!\n");
            out = TPM_ERROR;
#endif
            break;
        }
        case action_help:
            break;
    }

    switch(out){
        case SAVE_TO_FILE_ERROR:
            fprintf(stderr, "Error writing to a file\n");
            break;
        case READ_FROM_FILE_ERROR:
            fprintf(stderr, "Error reading from a file\n");
            break;
        case KEY_CREATION_ERROR:
            fprintf(stderr, "Error creating ecdsap256 keypair\n");
            break;
        case CERT_CREATION_ERROR:
            fprintf(stderr, "Error creating certificate\n");
            break;
        case ASN1_CREATION_ERROR:
            fprintf(stderr, "Error creating ASN.1 wrapped keys\n");
            break;
        case SERVER_ERROR:
            fprintf(stderr, "Error while server is running xtt\n");
            break;
        case CLIENT_ERROR:
            fprintf(stderr, "Error while client is running xtt\n");
            break;
        case TPM_ERROR:
            fprintf(stderr, "Error while trying to use TPM\n");
            break;
        case CRYPTO_HASH_ERROR:
            fprintf(stderr, "Error while generating the gid\n");
            break;
        case ASN1_PARSE_ERROR:
            fprintf(stderr, "Error parsing certificate: must pass in a certificate\n");
            break;
        case SUCCESS:
            fprintf(stderr, "ok\n");
            break;
        case VOID_SUCCESS:
            break;
    }

    if (0 == out) {
        return 0;
    } else {
        return 1;
    }
}
