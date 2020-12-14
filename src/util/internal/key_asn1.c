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

#include "key_asn1.h"

#include <stdint.h>
#include <string.h>

const size_t KEY_PRIVATE_KEY_OFFSET = 7;
const size_t KEY_PUBLIC_KEY_OFFSET = 56;

const unsigned char ASN1_PRIVATEKEY_FRAME[] = {
    // SEQUENCE, length=77(119)
    0x30, 0x77,

    // INTEGER, length=1, 1
    0x02, 0x01, 0x01,

    // OCTETSTRING, length=0x20(32)
    0x04, 0x20,
    // private key placeholder
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // CONSTRUCTED_0, length=0x0A(10)
    0xA0, 0x0A,
    // OBJECTIDENTIFIER, length=8
    0x06, 0x08,
    // PRIME256V1_OID
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,

    // CONSTRUCTED_1, length=0x44(68)
    0xA1, 0x44,
    // BITSTRING, length=0x42(66), no-bit-padding
    0x03, 0x42, 0x00,
    // public key placeholders
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
};

void
build_asn1_key(const xtt_ecdsap256_pub_key *pub_key,
               const xtt_ecdsap256_priv_key *priv_key,
               unsigned char *key_out)
{
    memcpy(key_out, ASN1_PRIVATEKEY_FRAME, sizeof(ASN1_PRIVATEKEY_FRAME));
    memcpy(&key_out[KEY_PUBLIC_KEY_OFFSET], pub_key->data, sizeof(xtt_ecdsap256_pub_key));
    memcpy(&key_out[KEY_PRIVATE_KEY_OFFSET], priv_key->data, sizeof(xtt_ecdsap256_priv_key));
}
