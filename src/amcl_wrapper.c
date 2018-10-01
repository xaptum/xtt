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

#include <amcl/ecdh_NIST256.h>
#include <sodium.h>
#include <xtt/crypto_wrapper.h>
#include <assert.h>

int xtt_crypto_create_ecdsap256_key_pair(xtt_ecdsap256_pub_key *pub_key, xtt_ecdsap256_priv_key *priv_key) {
    assert(sizeof(xtt_ecdsap256_pub_key) == 1+2*EFS_NIST256);
    assert(sizeof(xtt_ecdsap256_priv_key) == EGS_NIST256);
    xtt_crypto_get_random(priv_key->data, sizeof(xtt_ecdsap256_priv_key));
    octet pub = {.val = (char*)pub_key->data, .len = 0, .max = sizeof(xtt_ecdsap256_pub_key)};
    octet priv = {.val = (char*)priv_key->data, .len = sizeof(xtt_ecdsap256_priv_key), .max = sizeof(xtt_ecdsap256_priv_key)};
    int out = ECP_NIST256_KEY_PAIR_GENERATE(NULL, &priv, &pub);
    return out;
}

int xtt_crypto_sign_ecdsap256(unsigned char* signature_out,
                            const unsigned char* msg,
                            uint16_t msg_len,
                            const xtt_ecdsap256_priv_key* priv_key){
    assert(sizeof(xtt_ecdsap256_signature) == 2*EGS_NIST256);
    octet msg_in = {.val = (char *)msg, .len = msg_len, .max = msg_len};
    octet priv_sign_key_in = {.val = (char*)priv_key->data, .len = sizeof(xtt_ecdsap256_priv_key), .max = sizeof(xtt_ecdsap256_priv_key)};
    char ephem_key_buffer[EGS_NIST256];
    octet ephem_key = {.val = ephem_key_buffer, .len = sizeof(ephem_key_buffer), .max = sizeof(ephem_key_buffer)};
    xtt_crypto_get_random((unsigned char*)ephem_key.val, sizeof(ephem_key_buffer));

    octet c_comp = {.val = (char *)&signature_out[0], .len = EGS_NIST256, .max = EGS_NIST256};
    octet d_comp = {.val = (char *)&signature_out[EGS_NIST256], .len = EGS_NIST256, .max = EGS_NIST256};
    int out = ECP_NIST256_SP_DSA(SHA256, NULL, &ephem_key, &priv_sign_key_in, &msg_in, &c_comp, &d_comp);

    return out;
}

int xtt_crypto_verify_ecdsap256(const unsigned char* signature,
                              const unsigned char* msg,
                              uint16_t msg_len,
                              const xtt_ecdsap256_pub_key* pub_key){
    octet pub = {.val = (char *)pub_key->data, .len = sizeof(xtt_ecdsap256_pub_key), .max = sizeof(xtt_ecdsap256_pub_key)};
    octet msg_in = {.val = (char *)msg, .len = msg_len, .max = msg_len};
    octet c_comp = {.val = (char *)&signature[0], .len = EGS_NIST256, .max = EGS_NIST256};
    octet d_comp = {.val = (char *)&signature[EGS_NIST256], .len = EGS_NIST256, .max = EGS_NIST256};
    int out = ECP_NIST256_PUBLIC_KEY_VALIDATE(&pub);
    assert(0 == out);
    if (0 == out) {
        out = ECP_NIST256_VP_DSA(SHA256, &pub, &msg_in, &c_comp, &d_comp);
    }

    return out;
}
