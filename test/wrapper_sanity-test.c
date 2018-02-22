#include <xtt.h>

#include "test-utils.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>

void reinitialization_is_ok();
void size_sanity();
void x25519_keys_independent();
void dh_gives_same_secret();
void bad_dh_fails();
void good_ed25519_sign_succeeds();
void do_sign();

void initialize() {
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
    good_ed25519_sign_succeeds();
    do_sign();
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

void good_ed25519_sign_succeeds()
{
    printf("starting wrapper_sanity-test::good_ed25519_sign_succeeds...\n");

#if 0
#define message (unsigned char*)"test"
#define msg_len 4
#define addl_data (unsigned char*)"addl"
#define addl_len 4

    aead_chacha_keys client_handshake_keys;
    aead_chacha_keys server_handshake_keys;
    unsigned char ciphertext[msg_len + k_chacha_mac_length];
    uint32_t ciphertext_len;
    unsigned char rand_buf[42];
    unsigned char decrypted[msg_len];
    uint32_t decrypted_len;


    if (create_client_handshake_chacha_aead_keys(&client_handshake_keys, shared_secret_client_copy) != 0) {
        printf("Suspicious server public key!\n");
        return;
    }
    secure_clear(shared_secret_client_copy, k_x25519_shared_secret_length);

    if (do_x25519_diffie_hellman(shared_secret_server_copy, server_key_pair.priv, client_key_pair.pub) != 0) {
        printf("Server failed to do DH");
        return;
    }
    if (create_server_handshake_chacha_aead_keys(&server_handshake_keys, shared_secret_server_copy) != 0) {
        printf("Suspicious client public key!\n");
        return;
    }
    secure_clear(shared_secret_server_copy, k_x25519_shared_secret_length);

    get_random(rand_buf, 42);

    /* TODO: XOR the IV with the seq-num to get the nonce */
    aead_chacha_encrypt(ciphertext, &ciphertext_len, message, msg_len, addl_data, addl_len, client_handshake_keys.tx_iv, client_handshake_keys.tx);

    EXPECT_EQ(aead_chacha_decrypt(decrypted,
                                  &decrypted_len,
                                  ciphertext,
                                  ciphertext_len,
                                  addl_data,
                                  addl_len,
                                  server_handshake_keys.rx_iv,
                                  server_handshake_keys.rx),
             0);
#endif

    printf("ok\n");
}

void do_sign()
{
    printf("starting wrapper_sanity-test::do_sign...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len;
    xtt_ed25519_signature signature;
    xtt_ed25519_pub_key pub_key;
    xtt_ed25519_priv_key priv_key;

    msg_sign_len = sizeof(msg_sign);

    xtt_crypto_create_ed25519_key_pair(&pub_key, &priv_key);

    EXPECT_EQ(xtt_crypto_sign_ed25519(signature.data,
                                      msg_sign,
                                      msg_sign_len,
                                      &priv_key),
              0);

    EXPECT_EQ(xtt_crypto_verify_ed25519(signature.data,
                                        msg_sign, 
                                        msg_sign_len,
                                        &pub_key),
              0);

    printf("ok\n");
}
