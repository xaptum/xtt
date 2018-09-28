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
#include <xtt/util/generate_ecdsap256_keys.h>
#include <xtt/util/generate_x509_certificate.h>
#include <xtt/util/wrap_keys_asn1.h>
#include <xtt/util/root.h>
#include <xtt/util/generate_server_certificate.h>
#include <xtt/util/util_errors.h>
#include "parse_cli.h"
#include "infocert.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

int main(int argc, char **argv)
{
    struct cli_params params = {.privkey = NULL, .pubkey = NULL, .id = NULL, .cert = NULL, .asn1 = NULL, .server_id = NULL, .time=NULL,
                                .rootcert = NULL, .servercert = NULL, .basename = NULL, .serverpub = NULL, .serverpriv = NULL};
    parse_cli(argc, argv, &params);
    int out = 0;
    switch(params.command) {
        case action_genkey:
            out = xtt_generate_ecdsap256_keys(params.privkey, params.pubkey);
            break;
        case action_genx509cert:
            out = xtt_generate_x509_certificate(params.privkey, params.pubkey, params.id, params.cert);
            break;
        case action_wrapkeys:
            out = xtt_wrap_keys_asn1(params.privkey, params.pubkey, params.asn1);
            break;
        case action_genrootcert:
            out = xtt_generate_root(params.privkey, params.pubkey, params.id, params.rootcert);
            break;
        case action_genservercert:
            out = xtt_generate_server_certificate(params.rootcert, params.rootpriv, params.serverpriv,
                                                params.serverpub, params.server_id, params.time, params.servercert);
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
                out = PARSE_CERT_ERROR;
            }
            break;
        }
        case action_help:
            break;
    }

    switch(out){
        case SAVE_TO_FILE_ERROR:
            printf("Error writing to a file\n");
            break;
        case READ_FROM_FILE_ERROR:
            printf("Error reading from a file\n");
            break;
        case KEY_CREATION_ERROR:
            printf("Error creating ecdsap256 keypair\n");
            break;
        case CERT_CREATION_ERROR:
            printf("Error creating certificate\n");
            break;
        case ASN1_CREATION_ERROR:
            printf("Error creating ASN.1 wrapped keys\n");
            break;
        case EXPIRY_PASSED:
            printf("Expiry has already passed\n");
            break;
        case PARSE_CERT_ERROR:
            printf("Error parsing certificate: must pass in a certificate\n");
            break;
        case SUCCESS:
            printf("ok\n");
            break;
        case VOID_SUCCESS:
            break;
    }
}
