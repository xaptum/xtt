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
#include "infocert.h"
#include <xtt/crypto_types.h>
#include <xtt/certificates.h>
#include <xtt/util/asn1.h>
#include <xtt/util/root.h>
#include <xtt/util/util_errors.h>
#include <xtt/util/file_io.h>
#include <string.h>
#include <stdio.h>

struct xtt_server_certificate_raw_type;

static
void printf_hex(unsigned char* raw, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", raw[i]);
    }
    printf("\n");
}

static
void server_cert_out(struct xtt_server_certificate_raw_type* certificate)
{
    unsigned char* reserved = xtt_server_certificate_access_reserved(certificate);
    printf("Reserved: ");
    printf_hex(reserved, sizeof(xtt_certificate_reserved));

    unsigned char* root_id = xtt_server_certificate_access_rootid(certificate);
    printf("Root ID: ");
    printf_hex(root_id, sizeof(xtt_certificate_root_id));

    unsigned char* public_key = xtt_server_certificate_access_pubkey(certificate);
    printf("Public Key: ");
    printf_hex(public_key, sizeof(xtt_ecdsap256_pub_key));

    return;
}

static
void root_cert_out(xtt_root_certificate* root_certificate)
{
    xtt_certificate_root_id root_id;
    xtt_ecdsap256_pub_key public_key;
    xtt_deserialize_root_certificate(&public_key, &root_id, root_certificate);
    printf("Root ID: ");
    printf_hex(root_id.data, sizeof(xtt_certificate_root_id));

    printf("Public key: ");
    printf_hex(public_key.data, sizeof(xtt_ecdsap256_pub_key));
    return;
}


int info_cert(const char* filename, enum infocert_type type)
{
    int read_ret = 0;

    if (type == infocert_type_server) {
        unsigned char certificate[XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH];
        read_ret = xtt_read_from_file(filename, certificate, XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH);
        if(read_ret != XTT_SERVER_CERTIFICATE_ECDSAP256_LENGTH) {
            return READ_FROM_FILE_ERROR;
        }
        server_cert_out((struct xtt_server_certificate_raw_type*) certificate);
    } else if (type == infocert_type_root) {
        xtt_root_certificate root_certificate = {.data = {0}};
        read_ret = xtt_read_from_file(filename, root_certificate.data, sizeof(xtt_certificate_root_id)+sizeof(xtt_ecdsap256_pub_key));
        if(read_ret != sizeof(xtt_root_certificate)) {
            return READ_FROM_FILE_ERROR;
        }
        root_cert_out(&root_certificate);
    } else {
        return PARSE_CERT_ERROR;
    }

    return VOID_SUCCESS;
}
