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

#include <xtt/asn1_utilities.h>

#include "internal/asn1.h"

#include <xtt/crypto_wrapper.h>
#include <xtt/crypto_types.h>

#include <assert.h>
#include <string.h>

size_t xtt_x509_certificate_length(void)
{
    return XTT_X509_CERTIFICATE_LENGTH;
}

size_t xtt_asn1_private_key_length(void)
{
    return XTT_ASN1_PRIVATE_KEY_LENGTH;
}

int xtt_x509_from_ed25519_keypair(const xtt_ed25519_pub_key *pub_key_in,
                                  const xtt_ed25519_priv_key *priv_key_in,
                                  const xtt_identity_type *common_name,
                                  unsigned char *certificate_out)
{
    assert(XTT_X509_CERTIFICATE_LENGTH == get_certificate_length());

    unsigned char *pub_key_location;
    unsigned char *signature_location;
    unsigned char *signature_input_location;
    size_t signature_input_length;
    xtt_identity_string common_name_as_string;
    int convert_ret = xtt_identity_to_string(common_name, &common_name_as_string);
    if (0 != convert_ret)
        return -1;
    build_x509_skeleton(certificate_out, &pub_key_location, &signature_location, &signature_input_location, &signature_input_length, common_name_as_string.data);

    memcpy(pub_key_location, pub_key_in->data, sizeof(xtt_ed25519_pub_key));

    int sign_ret = xtt_crypto_sign_ed25519(signature_location, signature_input_location, signature_input_length, priv_key_in);
    if (0 != sign_ret) {
        return -1;
    } else {
        return 0;
    }
}

int xtt_asn1_from_ed25519_private_key(const xtt_ed25519_priv_key *priv_key_in,
                                      unsigned char *asn1_out)
{
    unsigned char *privkey_location;
    build_asn1_key_skeleton(asn1_out, &privkey_location);

    int ret = xtt_crypto_extract_ed25519_private_key(privkey_location, priv_key_in);
    if (0 != ret) {
        return -1;
    } else {
        return 0;
    }
}
