/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
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

#include <xtt/util/asn1.h>
#include <xtt/util/util_errors.h>
#include "internal/asn1.h"

#include <xtt/crypto_wrapper.h>
#include <xtt/crypto_types.h>
#include <xtt/util/file_io.h>

#include <assert.h>
#include <string.h>

#define XTT_ECDSAP256_PRIVATE_KEY_OFFSET 7
#define XTT_ECDSAP256_PUBLIC_KEY_OFFSET 56

size_t xtt_x509_certificate_length(void)
{
    return XTT_X509_CERTIFICATE_LENGTH;
}

size_t xtt_asn1_private_key_length(void)
{
    return XTT_ASN1_PRIVATE_KEY_LENGTH;
}

int xtt_x509_from_ecdsap256_keypair(const xtt_ecdsap256_pub_key *pub_key_in,
                                  const xtt_ecdsap256_priv_key *priv_key_in,
                                  const xtt_identity_type *common_name,
                                  unsigned char *certificate_out,
                                  size_t certificate_out_length)
{
    assert(XTT_X509_CERTIFICATE_LENGTH == get_certificate_length());

    unsigned char *pub_key_location;
    unsigned char *signature_location;
    unsigned char *signature_input_location;
    size_t signature_input_length;
    xtt_identity_string common_name_as_string;

    if (certificate_out_length < XTT_X509_CERTIFICATE_LENGTH)
      return CERT_CREATION_ERROR;

    int convert_ret = xtt_identity_to_string(common_name, &common_name_as_string);
    if (0 != convert_ret)
        return CERT_CREATION_ERROR;

    build_x509_skeleton(certificate_out, &pub_key_location, &signature_location, &signature_input_location, &signature_input_length, common_name_as_string.data);

    memcpy(pub_key_location, pub_key_in->data, sizeof(xtt_ecdsap256_pub_key));

    int sign_ret = xtt_crypto_sign_ecdsap256(signature_location, signature_input_location, signature_input_length, priv_key_in);

    if (0 != sign_ret) {
        return CERT_CREATION_ERROR;
    } else {
        return 0;
    }
}

int xtt_write_ecdsap256_keypair(xtt_ecdsap256_pub_key *pub_key, xtt_ecdsap256_priv_key *priv_key, const char *keypair_file)
{
    // 1) Create ASN.1 wrapped key pair
    unsigned char keypair[XTT_ASN1_PRIVATE_KEY_LENGTH] = {0};
    assert(XTT_ASN1_PRIVATE_KEY_LENGTH == get_asn1privatekey_length());

    unsigned char *privkey_location;
    unsigned char *pubkey_location;

    build_asn1_key_skeleton(keypair, &privkey_location, &pubkey_location);

    memcpy(privkey_location, priv_key->data, sizeof(xtt_ecdsap256_priv_key));

    memcpy(pubkey_location, pub_key->data, sizeof(xtt_ecdsap256_pub_key));

    // 2) Write key pair to file
    int save_ret = xtt_save_key_to_file(keypair, XTT_ASN1_PRIVATE_KEY_LENGTH, keypair_file);
    if (save_ret < 0) {
        return SAVE_TO_FILE_ERROR;
    }

    return 0;
}

int xtt_read_ecdsap256_keypair(const char* keypair_file, xtt_ecdsap256_pub_key *pub_key, xtt_ecdsap256_priv_key *priv_key)
{
    // 1) Read in key pair
    unsigned char keypair[XTT_ASN1_PRIVATE_KEY_LENGTH] = {0};
    int ret = xtt_read_from_file(keypair_file, keypair, XTT_ASN1_PRIVATE_KEY_LENGTH);
    if(ret < 0){
        return READ_FROM_FILE_ERROR;
    }

    // 2) Write each key to its structure
    memcpy(priv_key->data, &keypair[XTT_ECDSAP256_PRIVATE_KEY_OFFSET], sizeof(xtt_ecdsap256_priv_key));
    memcpy(pub_key->data, &keypair[XTT_ECDSAP256_PUBLIC_KEY_OFFSET], sizeof(xtt_ecdsap256_pub_key));

    return 0;

}
