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

#include "test-utils.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>

void ecdsa_regression_test();
void ecdsa_hard_code_keypair();
void ecdsa_hard_code_signature();
void ecdsa_check_k_vals();

void reinitialization_is_ok();
void size_sanity();
void x25519_keys_independent();
void dh_gives_same_secret();
void bad_dh_fails();

void initialize() {
    TEST_ASSERT(0 == ECDH_OK);
    int init_ret = xtt_crypto_initialize_crypto();
    TEST_ASSERT(0 == init_ret);
}

int main() {
    initialize();

    reinitialization_is_ok();
    size_sanity();
    x25519_keys_independent();
    dh_gives_same_secret();
    bad_dh_fails();

    ecdsa_regression_test();
    ecdsa_hard_code_keypair();
    ecdsa_hard_code_signature();
    ecdsa_check_k_vals();
}

void reinitialization_is_ok()
{
    printf("starting wrapper_sanity-test::reinitialization_is_ok...\n");

    int init_ret = xtt_crypto_initialize_crypto();
    EXPECT_EQ(init_ret, 0);

    printf("ok\n");
}

void size_sanity()
{
    printf("starting wrapper_sanity-test::size_sanity...\n");

    // TODO
    EXPECT_EQ(sizeof(xtt_x25519_pub_key), sizeof(xtt_x25519_priv_key));

    printf("ok\n");
}

void x25519_keys_independent()
{
    printf("starting wrapper_sanity-test::x25519_keys_independent...\n");

    xtt_x25519_pub_key pub;
    xtt_x25519_priv_key priv;
    xtt_crypto_create_x25519_key_pair(&pub, &priv);

    xtt_x25519_pub_key pub_two;
    xtt_x25519_priv_key priv_two;
    xtt_crypto_create_x25519_key_pair(&pub_two, &priv_two);

    // pub_key_length == priv_key_length (cf. earlier test)
    EXPECT_NE(memcmp(pub.data,
                     priv.data,
                     sizeof(xtt_x25519_pub_key)),
              0);

    EXPECT_NE(memcmp(pub_two.data,
                     priv_two.data,
                     sizeof(xtt_x25519_pub_key)),
              0);

    EXPECT_NE(memcmp(pub.data,
                     pub_two.data,
                     sizeof(xtt_x25519_pub_key)),
              0);

    EXPECT_NE(memcmp(priv.data,
                     priv_two.data,
                     sizeof(xtt_x25519_priv_key)),
              0);

    printf("ok\n");
}

void dh_gives_same_secret()
{
    printf("starting wrapper_sanity-test::dh_gives_same_secret...\n");

    xtt_x25519_pub_key client_pub;
    xtt_x25519_priv_key client_priv;
    xtt_crypto_create_x25519_key_pair(&client_pub, &client_priv);

    xtt_x25519_pub_key server_pub;
    xtt_x25519_priv_key server_priv;
    xtt_crypto_create_x25519_key_pair(&server_pub, &server_priv);

    xtt_x25519_shared_secret shared_secret_client_copy;
    EXPECT_EQ(xtt_crypto_do_x25519_diffie_hellman((unsigned char*)&shared_secret_client_copy,
                                                  &client_priv,
                                                  &server_pub),
              0);

    xtt_x25519_shared_secret shared_secret_server_copy;
    EXPECT_EQ(xtt_crypto_do_x25519_diffie_hellman((unsigned char*)&shared_secret_server_copy,
                                                  &server_priv,
                                                  &client_pub),
              0);

    EXPECT_EQ(memcmp(shared_secret_client_copy.data,
                     shared_secret_server_copy.data,
                     sizeof(xtt_x25519_shared_secret)),
              0);

    printf("ok\n");
}

void bad_dh_fails()
{
    printf("starting wrapper_sanity-test::bad_dh_fails...\n");

    xtt_x25519_pub_key client_pub;
    xtt_x25519_priv_key client_priv;
    xtt_crypto_create_x25519_key_pair(&client_pub, &client_priv);

    // Create garbage keys
    xtt_x25519_pub_key server_pub;
    xtt_x25519_priv_key server_priv;
    xtt_crypto_get_random(server_pub.data, sizeof(xtt_x25519_pub_key));
    xtt_crypto_get_random(server_priv.data, sizeof(xtt_x25519_priv_key));

    xtt_x25519_shared_secret shared_secret_client_copy;
    EXPECT_EQ(xtt_crypto_do_x25519_diffie_hellman((unsigned char*)&shared_secret_client_copy,
                                                  &client_priv,
                                                  &server_pub),
              0);

    xtt_x25519_shared_secret shared_secret_server_copy;
    EXPECT_EQ(xtt_crypto_do_x25519_diffie_hellman((unsigned char*)&shared_secret_server_copy,
                                                  &server_priv,
                                                  &client_pub),
              0);

    EXPECT_NE(memcmp(shared_secret_client_copy.data,
                     shared_secret_server_copy.data,
                     sizeof(xtt_x25519_shared_secret)),
              0);

    printf("ok\n");
}

void ecdsa_regression_test()
{
    printf("starting wrapper_sanity-test::ecdsa_regression_test...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len;
    xtt_ecdsap256_signature signature;
    xtt_ecdsap256_pub_key pub_key;
    xtt_ecdsap256_priv_key priv_key;

    msg_sign_len = sizeof(msg_sign);

    EXPECT_EQ(xtt_crypto_create_ecdsap256_key_pair(&pub_key, &priv_key), 0);
    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature.data, msg_sign, msg_sign_len, &priv_key), 0);
    EXPECT_EQ(xtt_crypto_verify_ecdsap256(signature.data, msg_sign, msg_sign_len, &pub_key), 0);
    printf("ok\n");
}

void ecdsa_hard_code_keypair(){
    printf("starting wrapper_sanity-test::ecdsa_hard_code_keypair...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len = sizeof(msg_sign);
    xtt_ecdsap256_signature signature;
    xtt_ecdsap256_pub_key pub_key = {.data = {0x04, 0xc6, 0x33, 0x28, 0x1d, 0x25, 0x3c, 0xe4, 0xc5, 0x61, 0xbd, 0xf4, 0x7f, 0xa3, 0x30,
    0x01, 0x9f, 0x85, 0x80, 0x12, 0x03, 0xd3, 0xe8, 0x84, 0x3b, 0x8d, 0xde, 0xd0, 0xd3, 0x12,
    0xc6, 0x14, 0x15, 0xf2, 0x72, 0xd4, 0x83, 0x44, 0xc2, 0x59, 0x01, 0x38, 0x72, 0x0c, 0x07,
    0xeb, 0x0f, 0x92, 0xce, 0xd8, 0xd6, 0x40, 0xca, 0xe4, 0x08, 0x9d, 0xa4, 0x89, 0x8b, 0xf3,
    0x36, 0xeb, 0x04, 0x82, 0x30}};
    xtt_ecdsap256_priv_key priv_key = {.data ={0x5a, 0xba, 0x8a, 0x98, 0x5e, 0xfc, 0xee, 0xd5, 0x08, 0x1d, 0x1c, 0x45, 0x84, 0xd5, 0x34,
    0x73, 0x8b, 0x1d, 0x1d, 0xb5, 0x65, 0xb9, 0xe3, 0x19, 0x8d, 0x08, 0x86, 0x12, 0x7d, 0x2d,
    0x88, 0x23}};

    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature.data, msg_sign, msg_sign_len, &priv_key), 0);

    EXPECT_EQ(xtt_crypto_verify_ecdsap256(signature.data, msg_sign, msg_sign_len, &pub_key), 0);
    printf("ok\n");

}

void ecdsa_hard_code_signature(){
    printf("starting wrapper_sanity-test::ecdsa_hard_code_signature...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len = sizeof(msg_sign);
    xtt_ecdsap256_signature signature = {.data = {0xf9, 0xc4, 0x22, 0x31, 0xb4, 0x2,
        0x73, 0x42, 0x44, 0x71, 0x1f, 0x3f, 0xca, 0xa4, 0x84, 0x3, 0xac, 0xd0, 0x9b,
        0xfc, 0xa5, 0xf3, 0x69, 0xae, 0x55, 0xc0, 0x31, 0xb9, 0x1, 0x7, 0xa7, 0x7f,
        0xfb, 0x17, 0x9a, 0x8f, 0xe1, 0x97, 0x2e, 0xc3, 0x90, 0x6a, 0xed, 0xfe,
        0xee, 0x30, 0xe2, 0x76, 0x51, 0x79, 0x50, 0x9c, 0xda, 0x48, 0x1, 0xc7, 0xb7,
        0x70, 0x5c, 0x10, 0xc2, 0xeb, 0xa4, 0x6f
}};
    xtt_ecdsap256_pub_key pub_key = {.data = {0x04, 0xc6, 0x33, 0x28, 0x1d, 0x25, 0x3c, 0xe4, 0xc5, 0x61, 0xbd, 0xf4, 0x7f, 0xa3, 0x30,
    0x01, 0x9f, 0x85, 0x80, 0x12, 0x03, 0xd3, 0xe8, 0x84, 0x3b, 0x8d, 0xde, 0xd0, 0xd3, 0x12,
    0xc6, 0x14, 0x15, 0xf2, 0x72, 0xd4, 0x83, 0x44, 0xc2, 0x59, 0x01, 0x38, 0x72, 0x0c, 0x07,
    0xeb, 0x0f, 0x92, 0xce, 0xd8, 0xd6, 0x40, 0xca, 0xe4, 0x08, 0x9d, 0xa4, 0x89, 0x8b, 0xf3,
    0x36, 0xeb, 0x04, 0x82, 0x30}};

    EXPECT_EQ(xtt_crypto_verify_ecdsap256(signature.data,
                                        msg_sign,
                                        msg_sign_len,
                                        &pub_key),
              0);
    printf("ok\n");
}

void ecdsa_check_k_vals(){
    printf("starting wrapper_sanity-test::ecdsa_check_k_vals...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len;
    xtt_ecdsap256_signature signature1;
    xtt_ecdsap256_signature signature2;
    xtt_ecdsap256_pub_key pub_key;
    xtt_ecdsap256_priv_key priv_key;

    msg_sign_len = sizeof(msg_sign);

    EXPECT_EQ(xtt_crypto_create_ecdsap256_key_pair(&pub_key, &priv_key), 0);

    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature1.data,
                                      msg_sign,
                                      msg_sign_len,
                                      &priv_key),
              0);
    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature2.data,
                                      msg_sign,
                                      msg_sign_len,
                                      &priv_key),
              0);

    EXPECT_NE(memcmp(signature1.data, signature2.data, sizeof(xtt_ecdsap256_signature)), 0);
    printf("ok\n");

}
