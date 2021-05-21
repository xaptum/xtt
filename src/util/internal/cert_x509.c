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

#include "cert_x509.h"

#include <xtt/crypto_wrapper.h>

#include <stdint.h>
#include <string.h>

const size_t TBS_OFFSET = 4;
const size_t TBS_LENGTH = 269;

const size_t LENGTH_OFFSET = 2;
const size_t SERIAL_NUMBER_OFFSET = 10;
const size_t COMMON_NAME_OFFSET = 55;
const size_t ISSUER_NAME_OFFSET = 143;
const size_t PUBLIC_KEY_OFFSET = 208;
const size_t SIGNATURE_BITSTRING_OFFSET = 286;
const size_t SIGNATURE_SEQUENCE_OFFSET = 289;

const unsigned char X509_PREAMBLE[] = {
    // - certificate -
    // SEQUENCE, TWO-BYTE-LENGTH, length=0x162(354)
    0x30, 0x82, 0x01, 0x62,
      // - tbs certificate -
      // SEQUENCE, TWO-BYTE-LENGTH, length=0x019(265)
      0x30, 0x82, 0x01, 0x09,
        // - serial number -
        // INTEGER, length=0x14(20)
        0x02, 0x14,
        // serial number placeholder
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        // - signature algorithm ID -
        // SEQUENCE, length=0x0A(10)
        0x30, 0x0A,
        // OBJECT_IDENTIFIER, length=8
        0x06, 0x08,
        // ECDSA_W_SHA256_OID
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,

        // - common name -
        // SEQUENCE, length=0x32(50)
        0x30, 0x32,
        // SET, length=0x30(48)
        0x31, 0x30,
        // SEQUENCE, length=0x2E(46)
        0x30, 0x2E,
        // OBJECT_IDENTIFIER, length=3
        0x06, 0x03,
        // COMMONNAME_OID
        0x55, 0x04, 0x03,
        // UTF8STRING_ATTRTYPE, length=0x27(39)
        0x0C, 0x27,
        // common name placeholder (fully-expanded canonical IPv6 string)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,

        // - validity -
        // SEQUENCE, length=0x22(34)
        0x30, 0x22,
        // GENERALIZED_TIME, length=0x0F(15)
        0x18, 0x0F,
        // "00000101000000Z" in ASCII
        0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
        // GENERALIZED_TIME, length=0x0F(15)
        0x18, 0x0F,
        // "99991231235959Z" in ASCII
        0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A,

        // - issuer name -
        // SEQUENCE, length=0x32(50)
        0x30, 0x32,
        // SET, length=0x30(48)
        0x31, 0x30,
        // SEQUENCE, length=0x2E(46)
        0x30, 0x2E,
        // OBJECT_IDENTIFIER, length=3
        0x06, 0x03,
        // COMMONNAME_OID
        0x55, 0x04, 0x03,
        // UTF8STRING_ATTRTYPE, length=0x27(39)
        0x0C, 0x27,
        // issuer name placeholder (fully-expanded canonical IPv6 string)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,

        // - public key -
        // SEQUENCE, length=0x59(89)
        0x30, 0x59,
        // SEQUENCE, length=0x13(19)
        0x30, 0x13,
        // OBJECT_IDENTIFIER, length=7
        0x06, 0x07,
        // ECPUBLICKEY_OID
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        // OBJECT_IDENTIFIER, length=8
        0x06, 0x08,
        // PRIME256V1_OID
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        // BITSTRING, length=0x42(66), no-bit-padding
        0x03, 0x42, 0x00,
        // public key placeholders
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,

        // - signature algorithm ID -
        // SEQUENCE, length=0x0A(10)
        0x30, 0x0A,
        // OBJECT_IDENTIFIER, length=8
        0x06, 0x08,
        // ECDSA_W_SHA256_OID
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,

        // - signature -
        // BITSTRING_TAG, length=0x47(71), no-bit-padding
        0x03, 0x47, 0x00,
        // SEQUENCE, length=0x44(68)
        0x30, 0x44,

        // two-INTEGER signature will be built here...
};

static void
generate_serial_number(unsigned char *certificate);

static void
build_signature_integer(const unsigned char *integer_in,
                        unsigned char *certificate,
                        unsigned char *output_pos,
                        size_t *length_written);

void
build_x509_preamble(const xtt_identity_string *common_name,
                    const xtt_ecdsap256_pub_key *pub_key,
                    unsigned char *certificate_out,
                    unsigned char **to_be_signed_location_out,
                    size_t *to_be_signed_length_out)
{
    const size_t ipv6_cn_length = 39;

    memcpy(certificate_out, X509_PREAMBLE, sizeof(X509_PREAMBLE));

    generate_serial_number(certificate_out);

    // Copy in the common_name (into both the CN and Issuer fields)
    memcpy(&certificate_out[COMMON_NAME_OFFSET], common_name->data, ipv6_cn_length);
    memcpy(&certificate_out[ISSUER_NAME_OFFSET], common_name->data, ipv6_cn_length);

    // Copy in the public key
    memcpy(&certificate_out[PUBLIC_KEY_OFFSET], pub_key->data, sizeof(xtt_ecdsap256_pub_key));

    *to_be_signed_location_out = certificate_out + TBS_OFFSET;
    *to_be_signed_length_out = TBS_LENGTH;
}

void
append_x509_signature(const unsigned char *signature_r,
                      const unsigned char *signature_s,
                      unsigned char *certificate_out)
{
    size_t first_int_size;
    build_signature_integer(signature_r,
                            certificate_out,
                            certificate_out + sizeof(X509_PREAMBLE),
                            &first_int_size);

    size_t second_int_size;
    build_signature_integer(signature_s,
                            certificate_out,
                            certificate_out + sizeof(X509_PREAMBLE) + first_int_size,
                            &second_int_size);
}

size_t
certificate_length(const unsigned char *certificate)
{
    return (certificate[LENGTH_OFFSET] << 8) +
        certificate[LENGTH_OFFSET+1] +
        TBS_OFFSET;
}

static void
generate_serial_number(unsigned char *certificate)
{
    // Nb. We're only generating 19 bytes of randomness
    xtt_crypto_get_random(&certificate[SERIAL_NUMBER_OFFSET], 19);
    certificate[SERIAL_NUMBER_OFFSET] &= 0x7F;   // clear msb, to ensure it's positive
}

static void
build_signature_integer(const unsigned char *integer_in,
                        unsigned char *certificate,
                        unsigned char *output_pos,
                        size_t *length_written)
{
    *length_written = 2 + P256_BIGNUM_SIZE;

    // INTEGER
    *output_pos = 0x02;
    ++output_pos;

    // length=P256_BIGNUM_SIZE (may be incremented below)
    *output_pos = P256_BIGNUM_SIZE;
    unsigned char *length_pos = output_pos;
    ++output_pos;

    // If msb is set, need to add leading 0-byte
    // (and update all lengths that include this INTEGER).
    if (0x80 & integer_in[0]) {
        *output_pos = 0;
        output_pos += 1;

        *length_pos += 1;

        certificate[LENGTH_OFFSET+1] += 1;  // increment second byte of two-byte length
        certificate[SIGNATURE_BITSTRING_OFFSET] += 1;
        certificate[SIGNATURE_SEQUENCE_OFFSET] += 1;

        *length_written += 1;
    }

    memcpy(output_pos, integer_in, P256_BIGNUM_SIZE);
}
