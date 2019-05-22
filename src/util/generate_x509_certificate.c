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
#include <xtt/crypto_types.h>
#include <xtt/crypto_wrapper.h>
#include <xtt/util/asn1.h>
#include <xtt/util/file_io.h>
#include <xtt/util/util_errors.h>
#include <xtt/util/generate_x509_certificate.h>

int xtt_generate_x509_certificate(const char *keypair_filename, const char *id_filename, const char *certificate_filename)
{
    int read_ret = 0;
    int write_ret = 0;
    int ret = 0;

    // 1) Read in key pair.
    xtt_ecdsap256_pub_key pub = {.data = {0}};
    xtt_ecdsap256_priv_key priv  = {.data = {0}};
    read_ret = xtt_read_ecdsap256_keypair(keypair_filename, &pub, &priv);
    if (read_ret != 0) {
        return read_ret;
    }

    // 2) Read in ID from file
    xtt_identity_type id = {.data = {0}};
    if (NULL != id_filename) {
        read_ret = xtt_read_from_file(id_filename, id.data, sizeof(xtt_identity_type));
        if (read_ret < 0) {
            return READ_FROM_FILE_ERROR;
        }
    } else
    {
        id = xtt_null_identity;
    }

    // 3) Create certificate and save to file.
    unsigned char cert_buf[XTT_X509_CERTIFICATE_LENGTH] = {0};
    ret = xtt_x509_from_ecdsap256_keypair(&pub, &priv, &id, cert_buf, sizeof(cert_buf));
    if (0 != ret) {
        return CERT_CREATION_ERROR;
    }

    write_ret = xtt_save_cert_to_file(cert_buf, sizeof(cert_buf), certificate_filename);
    if (write_ret < 0) {
        return SAVE_TO_FILE_ERROR;
    }

    return 0;
}
