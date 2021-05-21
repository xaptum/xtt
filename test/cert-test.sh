#!/bin/bash

set -e

if [[ $# -ne 2 ]]; then
        echo "usage: $0 <tool directory> <tmp directory>"
        exit 1
fi

tool_dir="$1"
tmp_dir="$2"

OPENSSL_MINOR_VERSION=$(openssl version | sed -E 's/OpenSSL 1.(.).*$/\1/')
echo $OPENSSL_MINOR_VERSION

CN="DEAD:0000:0000:0000:0000:0000:0000:BEEF"
CN_BYTES="\xDE\xAD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xBE\xEF"

echo "Generating keypair..."
${tool_dir}/xtt genkeypair -k ${tmp_dir}/keys.asn1.bin

echo "Validating keypair..."
openssl ec -in ${tmp_dir}/keys.asn1.bin -inform DER -noout $([ ${OPENSSL_MINOR_VERSION} -ge 1 ] && echo "-check")
echo "ok"

echo "Generating cert..."
echo -ne ${CN_BYTES} > ${tmp_dir}/id.bin
${tool_dir}/xtt genx509cert -k ${tmp_dir}/keys.asn1.bin -d ${tmp_dir}/id.bin -c ${tmp_dir}/cert.bin
openssl x509 -in ${tmp_dir}/cert.bin -inform DER -out ${tmp_dir}/cert.pem

# NOTE: The `-check_ss_sig` is VERY important here. Without it, the signature won't be checked.
echo "Verifying certificate..."
openssl verify -check_ss_sig -CAfile ${tmp_dir}/cert.pem ${tmp_dir}/cert.pem
echo "ok"

echo "Validating certificate dates (for non-expiring certificate)"
DATES=$(cat <<EOF
notBefore=Jan  1 00:00:00 0 GMT
notAfter=Dec 31 23:59:59 9999 GMT
EOF
)
test "${DATES}" = "$(openssl x509 -in ${tmp_dir}/cert.pem -noout -dates)"
echo "ok"

echo "Checking Issuer and Subject (should be the same)"
test 1 -eq $(openssl x509 -in ${tmp_dir}/cert.pem -noout -subject | grep -c ${CN})
test 1 -eq $(openssl x509 -in ${tmp_dir}/cert.pem -noout -issuer | grep -c ${CN})
echo "ok"
