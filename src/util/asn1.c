/******************************************************************************
 *
 * Copyright 2017-2020 Xaptum, Inc.
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
#include "internal/cert_x509.h"
#include "internal/key_asn1.h"

#include <xtt/crypto_wrapper.h>
#include <xtt/crypto_types.h>
#include <xtt/util/file_io.h>

#include <assert.h>
#include <string.h>

#define XTT_ECDSAP256_PRIVATE_KEY_OFFSET 7
#define XTT_ECDSAP256_PUBLIC_KEY_OFFSET 56

size_t xtt_x509_certificate_max_length(void)
{
    return XTT_X509_CERTIFICATE_MAX_LENGTH;
}

size_t xtt_asn1_private_key_length(void)
{
    return XTT_ASN1_PRIVATE_KEY_LENGTH;
}

#ifdef USE_TPM
int xtt_x509_from_ecdsap256_TPM(const xtt_ecdsap256_pub_key *pub_key_in,
                                const struct xtpm_key *priv_key_in,
                                TSS2_TCTI_CONTEXT *tcti_context,
                                const xtt_identity_type *common_name,
                                unsigned char *certificate_out,
                                size_t *certificate_length_out)
{
    if (*certificate_length_out < XTT_X509_CERTIFICATE_MAX_LENGTH)
        return CERT_CREATION_ERROR;

    xtt_identity_string common_name_as_string = {};
    if (0 != xtt_identity_to_string(common_name, &common_name_as_string))
        return CERT_CREATION_ERROR;

    unsigned char *to_be_signed_location = NULL;
    size_t to_be_signed_length = 0;
    build_x509_preamble(&common_name_as_string,
                        pub_key_in,
                        certificate_out,
                        &to_be_signed_location,
                        &to_be_signed_length);

    TPM2B_DIGEST hash = {};
    struct xtt_crypto_hmac xtt_hash = {};
    if (0 != xtt_crypto_hash_sha256(&xtt_hash, to_be_signed_location, to_be_signed_length))
        return CERT_CREATION_ERROR;
    memcpy(hash.buffer, &xtt_hash.buf, sizeof(xtt_crypto_sha256));
    hash.size = xtt_hash.len;

    TPMT_SIGNATURE tpm_signature = {};
    if (TSS2_RC_SUCCESS != xtpm_sign(tcti_context,
                                     priv_key_in,
                                     &hash,
                                     &tpm_signature))
        return CERT_CREATION_ERROR;

    append_x509_signature(&tpm_signature.signature.ecdsa.signatureR.buffer[0],
                          &tpm_signature.signature.ecdsa.signatureS.buffer[0],
                          certificate_out);

    *certificate_length_out = certificate_length(certificate_out);

    return 0;
}
#endif

int xtt_x509_from_ecdsap256_keypair(const xtt_ecdsap256_pub_key *pub_key_in,
                                    const xtt_ecdsap256_priv_key *priv_key_in,
                                    const xtt_identity_type *common_name,
                                    unsigned char *certificate_out,
                                    size_t *certificate_length_out)
{
    if (*certificate_length_out < XTT_X509_CERTIFICATE_MAX_LENGTH)
        return CERT_CREATION_ERROR;

    xtt_identity_string common_name_as_string = {};
    if (0 != xtt_identity_to_string(common_name, &common_name_as_string))
        return CERT_CREATION_ERROR;

    unsigned char *to_be_signed_location = NULL;
    size_t to_be_signed_length = 0;
    build_x509_preamble(&common_name_as_string,
                        pub_key_in,
                        certificate_out,
                        &to_be_signed_location,
                        &to_be_signed_length);

    unsigned char combined_sig[sizeof(xtt_ecdsap256_signature)] = {};
    if (0 != xtt_crypto_sign_ecdsap256(combined_sig,
                                       to_be_signed_location,
                                       to_be_signed_length,
                                       priv_key_in))
        return CERT_CREATION_ERROR;

    append_x509_signature(&combined_sig[0],
                          &combined_sig[P256_BIGNUM_SIZE],
                          certificate_out);

    *certificate_length_out = certificate_length(certificate_out);

    return 0;
}

int xtt_write_ecdsap256_keypair(xtt_ecdsap256_pub_key *pub_key, xtt_ecdsap256_priv_key *priv_key, const char *keypair_file)
{
    unsigned char keypair[XTT_ASN1_PRIVATE_KEY_LENGTH] = {0};

    build_asn1_key(pub_key, priv_key, keypair);

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
