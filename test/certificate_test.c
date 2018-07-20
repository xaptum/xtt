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
#include <amcl/x509.h>
#include <assert.h>
#include "test-utils.h"
#include "../src/internal/asn1.h"

#ifdef __cplusplus
extern "C" {
#endif

void check_OID(unsigned char* certificate, const unsigned char* oid, int index, int length);
int check_seq(unsigned char* certificate, int index);

int main(){
    xtt_ecdsap256_pub_key public_key;
    xtt_ecdsap256_priv_key private_key;

    xtt_crypto_create_ecdsap256_key_pair(&public_key, &private_key);

    unsigned char certificate[XTT_X509_CERTIFICATE_LENGTH];

    xtt_x509_from_ecdsap256_keypair(&public_key, &private_key, &xtt_null_identity, certificate, XTT_X509_CERTIFICATE_LENGTH);

    printf("Certifcate: ");
    for (size_t i = 0; i < XTT_X509_CERTIFICATE_LENGTH; i++) {
        if(certificate[i]<0x10 )
            printf("0%x", certificate[i]);
        else
            printf("%x", certificate[i]);
    }
    printf("\n");

    int index = 0;
    index += check_seq(certificate, index);
    index += check_seq(certificate, index);
    TEST_ASSERT(certificate[index] == INTEGER_TAG);
    index++;
    TEST_ASSERT(certificate[index] == 0x14);
    index++;
    index += serial_num_length-2;
    TEST_ASSERT(certificate[index] = SEQUENCE_TAG);
    index += 2;
    check_OID(certificate, &ECDSA_W_SHA256_OID[0], index, sizeof(ECDSA_W_SHA256_OID));
    index += ecdsap256_algid_length - 2;
    index += check_seq(certificate, index);
    TEST_ASSERT(certificate[index] == SET_TAG);
    index += 2;
    index += check_seq(certificate, index);
    check_OID(certificate, &COMMONNAME_OID[0], index, sizeof(COMMONNAME_OID));
    index += name_oid_length;
    TEST_ASSERT(certificate[index] == UTF8STRING_ATTRTYPE);
    index += name_string_length;
    index += check_seq(certificate, index);
    TEST_ASSERT(certificate[index] == UTCTIME_TAG);
    index += utctime_length;
    TEST_ASSERT(certificate[index] == UTCTIME_TAG);
    index += utctime_length;
    index += check_seq(certificate, index);
    TEST_ASSERT(certificate[index] == SET_TAG);
    index += 2;
    index += check_seq(certificate, index);
    check_OID(certificate, &COMMONNAME_OID[0], index, sizeof(COMMONNAME_OID));
    index += name_oid_length;
    TEST_ASSERT(certificate[index] == UTF8STRING_ATTRTYPE);
    index += name_string_length;
    index += check_seq(certificate, index);
    index += check_seq(certificate, index);
    check_OID(certificate, &ECPUBLICKEY_OID[0], index, sizeof(ECPUBLICKEY_OID));
    index += ecpublickey_oid_length;
    check_OID(certificate, &PRIME256V1_OID[0], index, sizeof(PRIME256V1_OID));
    index += prime256v1_oid_length;
    TEST_ASSERT(certificate[index] == BITSTRING_TAG);
    index += pubkey_bitstring_length;
    index += check_seq(certificate, index);
    check_OID(certificate, &ECDSA_W_SHA256_OID[0], index, sizeof(ECDSA_W_SHA256_OID));
    index += ecdsap256_algid_length - 2;
    TEST_ASSERT(certificate[index] == BITSTRING_TAG);
    index += signature_value_length;
    TEST_ASSERT( index == (int) get_certificate_length());
    printf("Generated certificate is correctly formatted\n");

    unsigned char asn1[XTT_ASN1_PRIVATE_KEY_LENGTH];
    xtt_asn1_from_ecdsap256_private_key(&private_key, &public_key, asn1, sizeof(asn1));

    printf("ASN1 from private key: ");
    for (size_t i = 0; i < XTT_ASN1_PRIVATE_KEY_LENGTH; i++) {
        if(asn1[i]<0x10 )
            printf("0%x", asn1[i]);
        else
            printf("%x", asn1[i]);
    }
    printf("\n");

    index = 0;

    index += check_seq(asn1, index);

    TEST_ASSERT(asn1[index] == INTEGER_TAG);
    index += 3;

    TEST_ASSERT(asn1[index] == OCTETSTRING_TAG);
    index += 2 + RAW_PRIVATE_KEY_LENGTH;

    TEST_ASSERT(asn1[index] == CONSTRUCTED_TAG0);
    index += 2;
    check_OID(asn1, &PRIME256V1_OID[0], index, sizeof(PRIME256V1_OID));
    index += prime256v1_oid_length;

    TEST_ASSERT(asn1[index] == CONSTRUCTED_TAG1);
    index += 2 + pubkey_bitstring_length;

    TEST_ASSERT(index == XTT_ASN1_PRIVATE_KEY_LENGTH);
    printf("Generated ASN.1 private key is correctly formatted\n");
}

void check_OID(unsigned char* certificate, const unsigned char* oid, int index, int length){
    TEST_ASSERT(certificate[index] == OBJECTIDENTIFIER_TAG);
    index+=2;
    for (int i = 0; i < length; i++){
        TEST_ASSERT(certificate[index+i] == oid[i]);
    }
}

int check_seq(unsigned char* certificate, int index){
    TEST_ASSERT(certificate[index] == SEQUENCE_TAG);
    index++;
    if (certificate[index] == 0x82){
        return 4;
    } else if (certificate[index] == 0x81){
        return 3;
    } else {
        return 2;
    }
}

#ifdef __cplusplus
}
#endif
